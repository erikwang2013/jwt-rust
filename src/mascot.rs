// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
//! 项目宠物「钥匙小卫 Kee」：钥匙柄=框架无关内核，刃上八齿=八个适配层，胸前盾牌=校验与黑名单

/// English name of the mascot.
pub const NAME: &str = "Kee";
/// Chinese name of the mascot.
pub const CN_NAME: &str = "钥匙小卫";
/// Project home page.
pub const HOME: &str = "https://github.com/erikwang2013/jwt-rust";

const ART: &str = r#"       .--------------.
      /   o        o   \
     |         ^        |
     |       \___/      |
      \        |       /
       '.      |     .'
         |     |     |
      .--+-----+-----+--.
     |      ( ### )      |
      '--+-----+-----+--'
         |     |     |
         |     |     +--.
         |     |     +--.
         |_____|_____|"#;

const GOLD: &str = "\x1b[38;5;214m";
const BLUE: &str = "\x1b[38;5;39m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";

/// 终端横幅：安装演示与命令行使用。`color=None` 时自动探测 TTY。
pub fn banner(color: Option<bool>) -> String {
    let color = color.unwrap_or_else(|| std::io::IsTerminal::is_terminal(&std::io::stdout()));
    let mut out = String::from("\n");
    for line in ART.lines() {
        if color {
            // ### 是胸前的盾牌（校验与黑名单）
            let code = if line.contains("###") { BLUE } else { GOLD };
            out.push_str(code);
            out.push_str(line);
            out.push_str(RESET);
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    out.push('\n');
    let (name, tagline) = ("erikwang2013/jwt-rust", "  ·  Rust 多框架 JWT 认证插件");
    let ready = format!("{CN_NAME} {NAME} 已就位 —— 一套核心 · 八框架通行");
    if color {
        out.push_str(&format!("  {BOLD}{name}{RESET}{DIM}{tagline}{RESET}\n"));
        out.push_str(&format!("  {GOLD}{ready}{RESET}\n"));
    } else {
        out.push_str(&format!("  {name}{tagline}\n"));
        out.push_str(&format!("  {ready}\n"));
    }
    // 首页链接有意不着色（与 PHP 版对齐），勿当漏色误改
    out.push_str(&format!("  {HOME}\n\n"));
    out
}

/// 宠物矢量形象（编译期内嵌 docs/pet.svg，对应 PHP Mascot::svg()）
pub fn svg() -> &'static str {
    include_str!("../docs/pet.svg")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_contains_mascot_identity() {
        let b = banner(Some(false));
        assert!(b.contains("钥匙小卫"));
        assert!(b.contains("jwt-rust"));
        assert!(b.contains(HOME));
        assert!(!b.contains("\x1b["), "强制无色时不得含 ANSI 转义");
    }

    #[test]
    fn banner_color_has_ansi() {
        assert!(banner(Some(true)).contains("\x1b["));
    }

    #[test]
    fn colored_and_plain_paths_are_isomorphic() {
        fn strip_ansi(s: &str) -> String {
            let mut out = String::new();
            let mut in_esc = false;
            for c in s.chars() {
                if c == '\x1b' {
                    in_esc = true;
                    continue;
                }
                if in_esc {
                    if c == 'm' {
                        in_esc = false;
                    }
                    continue;
                }
                out.push(c);
            }
            out
        }
        assert_eq!(strip_ansi(&banner(Some(true))), banner(Some(false)));
    }

    #[test]
    fn svg_embedded() {
        let s = svg();
        assert!(s.contains("<svg"));
        assert!(s.len() > 500);
    }
}
