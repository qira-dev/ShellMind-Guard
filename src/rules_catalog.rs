use clap::{Command, ValueEnum};
pub(crate) use smg_graph::rules::{RULE_CATALOG, find_rule_doc};

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompletionShell {
    Bash,
    Zsh,
    Fish,
    Powershell,
}

pub(crate) fn render_shell_completions(cmd: &Command, shell: CompletionShell) -> String {
    let subs: Vec<String> = cmd
        .get_subcommands()
        .filter(|s| !s.is_hide_set())
        .map(|s| s.get_name().to_string())
        .collect();
    let global_opts = "--color --help --version -h -V";
    match shell {
        CompletionShell::Bash => {
            let sub_list = subs.join(" ");
            let mut out = format!(
                "# Bash completion for smg / shellmind-guard\n_smg_completions() {{\n  local cur=\"${{COMP_WORDS[COMP_CWORD]}}\"\n  local sub=\"${{COMP_WORDS[1]:-}}\"\n  if [[ $COMP_CWORD -eq 1 ]]; then\n    COMPREPLY=($(compgen -W \"{sub_list} {global_opts}\" -- \"$cur\"))\n    return\n  fi\n  case \"$sub\" in\n"
            );
            for sc in cmd.get_subcommands().filter(|s| !s.is_hide_set()) {
                let opts: Vec<String> = sc
                    .get_arguments()
                    .filter_map(|a| a.get_long().map(|l| format!("--{l}")))
                    .collect();
                out.push_str(&format!(
                    "    {}) COMPREPLY=($(compgen -W \"{} {}\" -- \"$cur\")) ;;\n",
                    sc.get_name(),
                    opts.join(" "),
                    global_opts
                ));
            }
            out.push_str("  esac\n}\ncomplete -F _smg_completions smg\ncomplete -F _smg_completions shellmind-guard\n");
            out
        }
        CompletionShell::Zsh => {
            let mut out = String::from(
                "#compdef smg shellmind-guard\n_smg() {\n  local -a subcommands\n  subcommands=(\n",
            );
            for sc in cmd.get_subcommands().filter(|s| !s.is_hide_set()) {
                let desc = sc
                    .get_about()
                    .map(|a| a.to_string().replace('\'', " "))
                    .unwrap_or_default();
                out.push_str(&format!("    '{}:{}'\n", sc.get_name(), desc));
            }
            out.push_str("  )\n  _arguments '1:command:->cmds' '*::arg:->args'\n  case $state in\n    cmds) _describe 'command' subcommands ;;\n    args) case $line[1] in\n");
            for sc in cmd.get_subcommands().filter(|s| !s.is_hide_set()) {
                let opts: Vec<String> = sc
                    .get_arguments()
                    .filter_map(|a| a.get_long().map(|l| format!("--{l}")))
                    .collect();
                out.push_str(&format!(
                    "      {}) compadd -- {} ;;\n",
                    sc.get_name(),
                    opts.join(" ")
                ));
            }
            out.push_str("    esac ;;\n  esac\n}\ncompdef _smg smg shellmind-guard\n");
            out
        }
        CompletionShell::Fish => {
            let mut out = String::from("# Fish completions for smg / shellmind-guard\n");
            for bin in ["smg", "shellmind-guard"] {
                for sc in cmd.get_subcommands().filter(|s| !s.is_hide_set()) {
                    let desc = sc
                        .get_about()
                        .map(|a| a.to_string().replace('\'', " "))
                        .unwrap_or_default();
                    out.push_str(&format!(
                        "complete -c {bin} -f -n '__fish_use_subcommand' -a '{}' -d '{}'\n",
                        sc.get_name(),
                        desc
                    ));
                    for arg in sc.get_arguments() {
                        if let Some(long) = arg.get_long() {
                            out.push_str(&format!(
                                "complete -c {bin} -f -n '__fish_seen_subcommand_from {}' -l '{}'\n",
                                sc.get_name(),
                                long
                            ));
                        }
                    }
                }
            }
            out
        }
        CompletionShell::Powershell => {
            let sub_arr = subs
                .iter()
                .map(|s| format!("'{s}'"))
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "# PowerShell completion for smg / shellmind-guard\n@('smg', 'shellmind-guard') | ForEach-Object {{\n  Register-ArgumentCompleter -Native -CommandName $_ -ScriptBlock {{\n    param($wordToComplete, $commandAst, $cursorPosition)\n    @({sub_arr}) | Where-Object {{ $_ -like \"$wordToComplete*\" }} | ForEach-Object {{ [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }}\n  }}\n}}\n"
            )
        }
    }
}
