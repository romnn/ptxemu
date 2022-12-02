#![allow(warnings)]
// #![allow(dead_code)]

#[macro_use]
extern crate pest_derive;
#[macro_use]
extern crate pest_ast;
#[macro_use]
extern crate pest;

mod ast;
mod image;
mod ptx;

use crate::ptx::Rule;
use ast::{ASTNode, FunctionDeclHeader, ParseError};
use color_eyre::eyre;
use pest::iterators::Pair;
use pest::Parser;
use std::fs;
use std::path::{Path, PathBuf};

fn walk(pair: Pair<Rule>) -> eyre::Result<ASTNode> {
    match pair.as_rule() {
        Rule::function_defn => {
            let inner = pair.into_inner().map(|p| walk(p));
            println!("{:?}", inner.collect::<eyre::Result<Vec<ASTNode>>>());
            // Ok(ASTNode::FunctionDefn { name: "test" })
            Ok(ASTNode::FunctionDefn {})
        }
        Rule::function_decl => {
            let inner = pair.into_inner().map(|p| walk(p));
            println!("{:?}", inner.collect::<eyre::Result<Vec<ASTNode>>>());
            Ok(ASTNode::FunctionDecl { name: "test" })
        }
        Rule::function_ident_param => {
            // extract identifier and param_list
            let inner = pair.into_inner().map(|p| walk(p));
            println!("{:?}", inner.collect::<eyre::Result<Vec<ASTNode>>>());
            Ok(ASTNode::EOI)
        }
        Rule::function_decl_header => {
            let header = match pair.into_inner().next().map(|p| p.as_rule()) {
                Some(Rule::function_decl_header_entry) => Ok(FunctionDeclHeader::Entry),
                Some(Rule::function_decl_header_visible_entry) => {
                    Ok(FunctionDeclHeader::VisibleEntry)
                }
                Some(Rule::function_decl_header_weak_entry) => Ok(FunctionDeclHeader::WeakEntry),
                Some(Rule::function_decl_header_func) => Ok(FunctionDeclHeader::Func),
                Some(Rule::function_decl_header_visible_func) => {
                    Ok(FunctionDeclHeader::VisibleFunc)
                }
                Some(Rule::function_decl_header_weak_func) => Ok(FunctionDeclHeader::WeakFunc),
                Some(Rule::function_decl_header_extern_func) => Ok(FunctionDeclHeader::ExternFunc),
                _ => Err(ParseError::Unexpected(
                    "expected valid function decl header",
                )),
            }?;
            Ok(ASTNode::FunctionDeclHeader(header))
        }
        Rule::statement_block => {
            let inner = pair.into_inner().map(|p| walk(p));
            println!("{:?}", inner.collect::<eyre::Result<Vec<ASTNode>>>());
            Ok(ASTNode::EOI)
        }
        Rule::version_directive => {
            let mut iter = pair.into_inner();
            let double = iter.next().map(|p| walk(p)).unwrap();
            let newer = iter.next().map(|v| v.as_str() == "+").unwrap_or(false);

            match double {
                Ok(ASTNode::Double(version)) => Ok(ASTNode::VersionDirective { version, newer }),
                _ => unreachable!(),
            }
        }
        Rule::target_directive => {
            let identifiers: Vec<&str> = pair
                .into_inner()
                .flat_map(|id| match id.as_rule() {
                    Rule::identifier => Some(id.as_str()),
                    _ => None,
                })
                .collect();
            Ok(ASTNode::TargetDirective(identifiers))
        }
        Rule::address_size_directive => {
            let size: u32 = pair
                .into_inner()
                .next()
                .and_then(|s| s.as_str().parse().ok())
                .unwrap();
            Ok(ASTNode::AddressSizeDirective(size))
        }
        Rule::file_directive => {
            let mut inner = pair.into_inner().map(|p| walk(p));
            let id: usize = match inner.next() {
                Some(Ok(ASTNode::SignedInt(value))) => Ok(value.try_into()?),
                Some(Ok(ASTNode::UnsignedInt(value))) => Ok(value.try_into()?),
                _ => Err(ParseError::Unexpected("expected id")),
            }?;
            let path: PathBuf = match inner.next() {
                Some(Ok(ASTNode::Str(value))) => Ok(value.into()),
                _ => Err(ParseError::Unexpected("expected file path")),
            }?;
            let size: Option<usize> = match inner.next() {
                Some(Ok(ASTNode::SignedInt(value))) => Some(value.try_into()?),
                Some(Ok(ASTNode::UnsignedInt(value))) => Some(value.try_into()?),
                _ => None,
            };
            let lines: Option<usize> = match inner.next() {
                Some(Ok(ASTNode::SignedInt(value))) => Some(value.try_into()?),
                Some(Ok(ASTNode::UnsignedInt(value))) => Some(value.try_into()?),
                _ => None,
            };
            Ok(ASTNode::FileDirective {
                id,
                path,
                size,
                lines,
            })
        }
        Rule::identifier => Ok(ASTNode::Identifier(pair.as_str())),
        Rule::string => Ok(ASTNode::Str(pair.as_str())),
        Rule::double => {
            // let value = pair.as_str();
            // todo
            Ok(ASTNode::Double(0f64))
        }
        Rule::integer => {
            let value = pair.as_str();
            let unsigned = value.ends_with("U");
            if value.starts_with("0b") || value.starts_with("0B") {
                // binary
                return if unsigned {
                    Ok(ASTNode::UnsignedInt(u64::from_str_radix(
                        &value[2..value.len() - 1],
                        2,
                    )?))
                } else {
                    Ok(ASTNode::SignedInt(i64::from_str_radix(&value[2..], 2)?))
                };
            }
            if value.ends_with("U") {
                Ok(ASTNode::UnsignedInt(
                    value[..value.len() - 1].parse::<u64>()?,
                ))
            } else {
                Ok(ASTNode::SignedInt(value.parse::<i64>()?))
            }
            // let decimal = ;
            // hex: sscanf(yytext,"%x", &yylval->int_value
            // decimal: atoi(yytext)
        }
        Rule::EOI => Ok(ASTNode::EOI),
        other => {
            eprintln!("unhandled rule: {:?}", other);
            Ok(ASTNode::EOI)
        } // Rule::number => str::parse(pair.as_str()).unwrap(),
          // Rule::sum => {
          //     let mut pairs = pair.into_inner();

          //     let num1 = pairs.next().unwrap();
          //     let num2 = pairs.next().unwrap();

          //     process(num1) + process(num2)
          // }
    }
}

pub fn gpgpu_ptx_sim_load_ptx_from_filename(path: &Path) -> eyre::Result<u32> {
    let source = fs::read_to_string(path)?;
    // let source = String::from_utf8(fs::read(path)?)?;
    let parse_tree = ptx::Parser::parse(ptx::Rule::program, &source)?;

    // let ast: Program = parse_tree.try_into()?;
    // Program::from(&parse_tree);
    let ast = parse_tree
        // .iter()
        // .flat_map(|pair| walk(pair))
        .map(|pair| walk(pair))
        // match pair.as_rule() {
        // Rule::version_directive => {
        //   println!("{:?}", pair);
        //   // let mut pairs = pair.into_inner();
        //   let version = 0.1f64;
        //   let newer = false;
        //   // let version = pairs.next().unwrap();
        //   // let newer = pairs.next().ok();
        //   Some(Statement::Directive(Directive::Version { version, newer }))
        // }
        // Rule::EOI => None,
        // other => {
        //   eprintln!("unhandled rule: {:?}", other);
        //   None
        // }
        // )
        .collect::<eyre::Result<Vec<ASTNode>>>()?;
    println!("ast = {:#?}", ast);

    // for record in parse_tree {
    // println!("{:?}", record.as_rule());
    // match record.as_rule() {
    //     Rule::directive => {
    //         record_count += 1;

    //         for field in record.into_inner() {
    //             field_sum += field.as_str().parse::<f64>().unwrap();
    //         }
    //     }
    //     Rule::EOI => (),
    //     other => panic!("unhandled rule: {}", other),
    // }
    // }

    // println!("parse tree = {:#?}", parse_tree);
    // let ast: Program = File::from_pest(&mut parse_tree).expect("infallible");
    // println!("syntax tree = {:#?}", syntax_tree);
    // println!();
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use eyre::eyre;
    use std::path::PathBuf;
    use testcontainers::*;

    macro_rules! ast_tests {
        ($($name:ident: $value:expr,)*) => {
            $(
                #[test]
                fn $name() -> eyre::Result<()> {
                    let (rule, source, expected) = $value;
                    let nodes = ptx::Parser::parse(rule, &source)?
                        .map(|p| walk(p))
                        .collect::<eyre::Result<Vec<ASTNode>>>()?;
                    assert_eq!(Some(expected), nodes.into_iter().next());
                    Ok(())
                }
            )*
        }
    }

    ast_tests! {
        ast_integer_decimal_0: (
            ptx::Rule::integer, "0", ASTNode::SignedInt(0)),
        ast_integer_decimal_1: (
            ptx::Rule::integer, "-12", ASTNode::SignedInt(-12)),
        ast_integer_decimal_2: (
            ptx::Rule::integer, "12U", ASTNode::UnsignedInt(12)),
        ast_integer_decimal_3: (
            ptx::Rule::integer, "01110011001", ASTNode::SignedInt(1110011001)),
        ast_integer_binary_0: (
            ptx::Rule::integer, "0b01110011001", ASTNode::SignedInt(921)),
        ast_integer_binary_1: (
            ptx::Rule::integer, "0b01110011001U", ASTNode::UnsignedInt(921)),
    }

    #[test]
    fn build_ast() -> eyre::Result<()> {
        let ptx_file = PathBuf::from("../kernels/mm/small.ptx");
        gpgpu_ptx_sim_load_ptx_from_filename(&ptx_file)?;
        Ok(())
    }

    #[test]
    fn test_docker_ptx_compile() -> eyre::Result<()> {
        let docker = clients::Cli::default();
        let cuda_container = crate::image::CUDA::default();
        let node = docker.run(cuda_container);
        // let minio = images::minio::MinIO::default();
        Ok(())
    }

    mod cuda_samples {
        use color_eyre::eyre::{self, WrapErr};
        use std::path::{Path, PathBuf};
        use testcontainers::core::Container;
        use testcontainers::{clients::Cli as DockerClient, core::ExecCommand};

        fn copy_dir_all(src: impl AsRef<Path>, dest: impl AsRef<Path>) -> eyre::Result<()> {
            std::fs::create_dir_all(&dest).wrap_err(format!(
                "failed to create dirs for {}",
                dest.as_ref().display()
            ))?;
            let mut entries = std::fs::read_dir(&src)
                .wrap_err(format!("failed to read dir {}", src.as_ref().display()))?;
            for entry in entries {
                let entry = entry.wrap_err(format!(
                    "failed to get file entry of {}",
                    src.as_ref().display()
                ))?;
                let file_type = entry.file_type().wrap_err(format!(
                    "failed to get file type for {}",
                    entry.path().display()
                ))?;
                let dest_entry = dest.as_ref().join(entry.file_name());
                if file_type.is_dir() {
                    copy_dir_all(entry.path(), &dest_entry)?;
                } else {
                    std::fs::copy(entry.path(), &dest_entry).wrap_err(format!(
                        "failed to copy {} to {}",
                        entry.path().display(),
                        dest_entry.display()
                    ))?;
                }
            }
            Ok(())
        }

        macro_rules! parser_tests {
            ($($name:ident: $values:expr,)*) => {
                $(
                    #[allow(non_snake_case)]
                    #[tokio::test(flavor = "multi_thread")]
                    async fn $name() -> eyre::Result<()> {
                        color_eyre::install()?;

                        let path = $values;
                        let application = PathBuf::from(env!("CARGO_WORKSPACE_DIR")).join(&path);
                        println!("validation workload path: {:?}", application);

                        // copy to a temp dir
                        let dir = tempfile::tempdir()?;
                        copy_dir_all(&application, dir.path())?;

                        // start CUDA container with this volume
                        let docker = DockerClient::default();

                        let mut image = testcontainers::image::generic::GenericImage {
                            name: "nvidia/cuda",
                            tag: "11.7.0-devel-ubuntu20.04",
                            ..Default::default()
                            // volumes: BTreeMap<String, String>,
                            // env_vars: BTreeMap<String, String>,
                            // wait_for: Vec<WaitFor>,
                            // entrypoint: Option<String>,
                            // exposed_ports: Vec<u16>,
                        };

                        // let mut image = crate::image::CUDA::default();
                        // let dest = PathBuf::from("/workload");
                        let dest = "/workload";
                        image.with_volume(dir.path(), &dest);

                        // todo: install dependencies and run make"
                        // let entrypoint = "make"
                        // run the make command and stream the output
                        let cmd = vec![
                            "make",
                            "-C",
                            dest, // .to_string_lossy().to_string().as_str(),
                            "-J",
                        ];
                        println!("runnings command {}", cmd.join(" "));
                        // let container = docker.run(request).await;
                        // container.exec(ExecCommand {
                        //     cmd: cmd.join(" "),
                        //     ready_conditions: vec![],
                        // });

                        image.with_entrypoint(cmd.join(" "));

                        println!("starting container");
                        let container = docker.run(image);


                        println!("{}", container.stdout_logs());
                        println!("{}", container.stderr_logs());
                        // wait a few seconds
                        // std::thread::sleep(std::time::Duration::from_secs(30));

                        // assert_eq!(Color::hex(hex).ok(), rgba);
                        Ok(())
                    }
                )*
            }
        }

        parser_tests! {
            dmmaTensorCoreGemm: "validation/cuda-samples/Samples/3_CUDA_Features/dmmaTensorCoreGemm",
        }
    }
}
// use std::path::Path;

// symbol_table *gpgpu_context::gpgpu_ptx_sim_load_ptx_from_filename(
//     const char *filename) {
//   symbol_table *symtab = init_parser(filename);
//   printf("GPGPU-Sim PTX: finished parsing EMBEDDED .ptx file %s\n", filename);
//   return symtab;
// }
//
// pub fn gpgpu_ptx_sim_load_ptx_from_filename(path: &Path) -> u32 {
//     let ptx_code = "

// .version 6.4
// .target sm_75
// .address_size 64

//     ";
//     0
// }

// symbol_table *gpgpu_context::init_parser(const char *ptx_filename) {
//   g_filename = strdup(ptx_filename);
//   if (g_global_allfiles_symbol_table == NULL) {
//     g_global_allfiles_symbol_table =
//         new symbol_table("global_allfiles", 0, NULL, this);
//     ptx_parser->g_global_symbol_table = ptx_parser->g_current_symbol_table =
//         g_global_allfiles_symbol_table;
//   }
// #define DEF(X, Y) g_ptx_token_decode[X] = Y;
// #include "ptx_parser_decode.def"
// #undef DEF
//   g_ptx_token_decode[undefined_space] = "undefined_space";
//   g_ptx_token_decode[undefined_space] = "undefined_space=0";
//   g_ptx_token_decode[reg_space] = "reg_space";
//   g_ptx_token_decode[local_space] = "local_space";
//   g_ptx_token_decode[shared_space] = "shared_space";
//   g_ptx_token_decode[param_space_unclassified] = "param_space_unclassified";
//   g_ptx_token_decode[param_space_kernel] = "param_space_kernel";
//   g_ptx_token_decode[param_space_local] = "param_space_local";
//   g_ptx_token_decode[const_space] = "const_space";
//   g_ptx_token_decode[tex_space] = "tex_space";
//   g_ptx_token_decode[surf_space] = "surf_space";
//   g_ptx_token_decode[global_space] = "global_space";
//   g_ptx_token_decode[generic_space] = "generic_space";
//   g_ptx_token_decode[instruction_space] = "instruction_space";

//   ptx_lex_init(&(ptx_parser->scanner));
//   ptx_parser->init_directive_state();
//   ptx_parser->init_instruction_state();

//   FILE *ptx_in;
//   ptx_in = fopen(ptx_filename, "r");
//   ptx_set_in(ptx_in, ptx_parser->scanner);
//   ptx_parse(ptx_parser->scanner, ptx_parser);
//   ptx_in = ptx_get_in(ptx_parser->scanner);
//   ptx_lex_destroy(ptx_parser->scanner);
//   fclose(ptx_in);
//   return ptx_parser->g_global_symbol_table;
// }
//
