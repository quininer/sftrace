use std::{io, fs};
use std::path::Path;
use std::io::BufRead;
use std::collections::HashMap;
use indexmap::IndexSet;
use polars::io::parquet;
use polars::prelude::*;
use crate::layout;
use crate::util::ArgsData;
use super::State;


#[derive(Default)]
pub struct PacketWriter {
    stack: HashMap<u32, Vec<(u32, u64)>>,
    funcs: IndexSet<u64>,
    names: Vec<String>,
    files: Vec<String>,
}

impl PacketWriter {
    pub fn convert(mut self, mut log: &mut io::BufReader<fs::File>, state: &mut State, path: &Path)
        -> anyhow::Result<()>
    {   
        let packet_schema = {
            let mut schema = Schema::with_capacity(8);
            schema.with_column("frame_id".into(), DataType::UInt64);
            schema.with_column("parent".into(), DataType::UInt64);
            schema.with_column("tid".into(), DataType::UInt32);
            schema.with_column("func_id".into(), DataType::UInt64);
            schema.with_column("time".into(), DataType::Duration(TimeUnit::Nanoseconds));
            schema.with_column("kind".into(), DataType::UInt32);
            // FIXME
            // Error: parquet: File out of specification: The number of columns in the row group (8) must be equal to the number of columns in the schema (10)
            // 
            // schema.with_column("args".into(), DataType::List(Box::new(DataType::Struct(vec![
            //     Field::new("name".into(), DataType::String),
            //     Field::new("value".into(), DataType::UInt128),
            // ]))));
            // schema.with_column("retval".into(), DataType::List(Box::new(DataType::Struct(vec![
            //     Field::new("name".into(), DataType::String),
            //     Field::new("value".into(), DataType::UInt128),
            // ]))));
            schema
        };
        
        let output = fs::File::create(path)?;
        let output = parquet::write::ParquetWriter::new(output);
        let mut output = output.batched(&packet_schema)?;
        let mut frame_id: u64 = 0;

        let mut columns = PacketSchema::default();

        macro_rules! frame_push {
            ( $( $key:ident => $value:expr ),* $( , )? ) => {
                $(
                    columns.$key.push($value);
                )*
            }
        }        

        while !log.fill_buf()?.is_empty() {
            let event: layout::Event<ArgsData, ArgsData, layout::AllocEvent> =
                cbor4ii::serde::from_reader(&mut log)?;

            match event.kind {
                layout::Kind::ENTRY => {
                    frame_id += 1;

                    let stack = self.stack.entry(event.tid).or_default();
                    let (_, parent) = stack.last().copied().unwrap_or_default();
                    stack.push((event.func_id, frame_id));

                    let entry_func = state
                        .entry_map
                        .get(state.section_offset, event.func_id)
                        .function();

                    if self.funcs.insert(entry_func)
                        && let Some(frame) = state.loader.lookup(entry_func)
                    {
                        self.names.push(frame.name);
                        self.files.push(format!("{}:{}", frame.file.unwrap_or_default(), frame.line.unwrap_or_default()));
                    }
                    
                    frame_push!{
                        frame_id => frame_id,
                        parent => parent,
                        tid => event.tid,
                        func_id => entry_func,
                        time => AnyValue::Duration(event.time as i64, TimeUnit::Nanoseconds),
                        kind => event.kind.as_u8() as u32,
                        // args => args_data(event.args.as_ref()),
                        // retval => args_data(event.args.as_ref()),
                    }
                },
                layout::Kind::EXIT | layout::Kind::TAIL_CALL => {
                    let mut has_entry = false;
                    let mut is_empty = false;

                    let mut entry_frame_id = None;
                    let mut parent = None;
                    let exit_func = state
                        .entry_map
                        .get(state.section_offset, event.func_id)
                        .function();                    

                    if let Some(stack) = self.stack.get_mut(&event.tid) {
                        if let Some((entry_func_id, frame_id)) = stack.pop() {
                            has_entry = true;
                            entry_frame_id = Some(frame_id);

                            let entry_func = state
                                .entry_map
                                .get(state.section_offset, entry_func_id)
                                .function();

                            if entry_func != exit_func {
                                eprintln!(
                                    "func id does not match: {:?} vs {:?}",
                                    entry_func_id, event.func_id
                                );
                            }
                        }

                        parent = stack.last().map(|(_, frame_id)| *frame_id);
                        is_empty = stack.is_empty();
                    }

                    if !has_entry {
                        eprintln!("missing entry event: {:?}", event);
                    }

                    if is_empty {
                        self.stack.remove(&event.tid);
                    }
                                  
                    frame_push!{
                        frame_id => entry_frame_id.unwrap_or_default(),
                        parent => parent.unwrap_or_default(),
                        tid => event.tid,
                        func_id => exit_func,
                        time => AnyValue::Duration(event.time as i64, TimeUnit::Nanoseconds),
                        kind => event.kind.as_u8() as u32,
                        // args => args_data(event.args.as_ref()),
                        // retval => args_data(event.return_value.as_ref()),
                    }

                },
                // temp ignore
                layout::Kind::ALLOC
                | layout::Kind::DEALLOC
                | layout::Kind::REALLOC_ALLOC
                | layout::Kind::REALLOC_DEALLOC => (),
                _ => (),
            }

            if columns.frame_id.len() > (4 * 1024) {
                let df = columns.collect_dataframe()?;
                output.write_batch(&df)?;
            }
        }

        if !columns.frame_id.is_empty() {
            let df = columns.collect_dataframe()?;
            output.write_batch(&df)?;
        }
        output.finish()?;

        // export symbol table
        let mut df = DataFrame::new_infer_height(vec![
            Column::new("func_id".into(), self.funcs.into_iter().collect::<Vec<_>>()),
            Column::new("name".into(), self.names),
            Column::new("file".into(), self.files),
        ])?;
        let output = fs::File::create(path.with_added_extension("symtab"))?;
        let output = parquet::write::ParquetWriter::new(output);
        output.finish(&mut df)?;
        
        Ok(())
    }
}

#[derive(Default)]
struct PacketSchema {
    frame_id: Vec<u64>,
    parent: Vec<u64>,
    tid: Vec<u32>,
    func_id: Vec<u64>,
    time: Vec<AnyValue<'static>>,
    kind: Vec<u32>,
    // args: Vec<AnyValue<'a>>,
    // retval: Vec<AnyValue<'a>>
}

// fn args_data(args: Option<&ArgsData>) -> AnyValue<'static> {
//     let args = args
//         .iter()
//         .flat_map(|args| args.0.vec.iter())
//         .map(|(name, value)| AnyValue::StructOwned(Box::new((
//             vec![AnyValue::StringOwned(name.into()), AnyValue::UInt128(*value)],
//             vec![Field::new("name".into(), DataType::String), Field::new("value".into(), DataType::UInt128)],
//         ))))
//         .collect::<Vec<_>>();
//     let args = Series::new("kv".into(), &args);
//     AnyValue::List(args)
// }

impl PacketSchema {
    fn collect_dataframe(&mut self) -> anyhow::Result<DataFrame> {
        macro_rules! frame_collect {
            ( $( $key:ident ),* $( , )? ) => {
                DataFrame::new_infer_height(vec![
                    $(
                        Column::new(stringify!($key).into(), self.$key.drain(..).collect::<Vec<_>>()),
                    )*
                ])
            }
        }

        let df = frame_collect!(
            frame_id,
            parent,
            tid,
            func_id,
            time,
            kind,
            // args,
            // retval,
        )?;

        Ok(df)
    }
}
