// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
//! 项目宠物「钥匙小卫 Kee」：卡通橘猫——猫有九命=九种接入，八根胡须=八个适配层，爪中钥匙=JWT，颈圈蓝盾=校验与黑名单；12 种表情形态见 `Expression`

/// English name of the mascot.
pub const NAME: &str = "Kee";
/// Chinese name of the mascot.
pub const CN_NAME: &str = "钥匙小卫";
/// Project home page.
pub const HOME: &str = "https://github.com/erikwang2013/jwt-rust";

const ART: &str = r#"       /\_/\
      ( o.o )
       > ^ <
      /|   |\
     / |###| \
    (  |___|  )
     \_/   \_/"#;

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
    // 首页链接有意不着色，勿当漏色误改
    out.push_str(&format!("  {HOME}\n\n"));
    out
}

/// 宠物矢量形象（编译期内嵌 docs/pet.svg）
pub fn svg() -> &'static str {
    include_str!("../docs/pet.svg")
}

/// 宠物的 12 种表情形态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Expression {
    Smile,
    Joy,
    Cry,
    Depressed,
    Terrified,
    Angry,
    Coquettish,
    Cute,
    Pleasing,
    Knocking,
    Facepalm,
    Tongue,
}

impl Expression {
    /// 全部 12 种形态，顺序与 README 的表情表一致。
    pub const ALL: [Self; 12] = [
        Self::Smile,
        Self::Joy,
        Self::Cry,
        Self::Depressed,
        Self::Terrified,
        Self::Angry,
        Self::Coquettish,
        Self::Cute,
        Self::Pleasing,
        Self::Knocking,
        Self::Facepalm,
        Self::Tongue,
    ];

    /// 英文标识，与 SVG 文件名一致。
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Smile => "smile",
            Self::Joy => "joy",
            Self::Cry => "cry",
            Self::Depressed => "depressed",
            Self::Terrified => "terrified",
            Self::Angry => "angry",
            Self::Coquettish => "coquettish",
            Self::Cute => "cute",
            Self::Pleasing => "pleasing",
            Self::Knocking => "knocking",
            Self::Facepalm => "facepalm",
            Self::Tongue => "tongue",
        }
    }

    /// 中文名，与 README 的表情表一致。
    #[must_use]
    pub const fn cn_name(self) -> &'static str {
        match self {
            Self::Smile => "笑",
            Self::Joy => "欢乐",
            Self::Cry => "哭",
            Self::Depressed => "沮丧",
            Self::Terrified => "惊恐",
            Self::Angry => "愤怒",
            Self::Coquettish => "撒娇",
            Self::Cute => "卖萌",
            Self::Pleasing => "讨好",
            Self::Knocking => "敲打",
            Self::Facepalm => "捂脸",
            Self::Tongue => "吐舌头",
        }
    }

    /// 对应的 SVG 形象（编译期内嵌 docs/pet-expressions/*.svg）。
    #[must_use]
    pub const fn svg(self) -> &'static str {
        match self {
            Self::Smile => include_str!("../docs/pet-expressions/smile.svg"),
            Self::Joy => include_str!("../docs/pet-expressions/joy.svg"),
            Self::Cry => include_str!("../docs/pet-expressions/cry.svg"),
            Self::Depressed => include_str!("../docs/pet-expressions/depressed.svg"),
            Self::Terrified => include_str!("../docs/pet-expressions/terrified.svg"),
            Self::Angry => include_str!("../docs/pet-expressions/angry.svg"),
            Self::Coquettish => include_str!("../docs/pet-expressions/coquettish.svg"),
            Self::Cute => include_str!("../docs/pet-expressions/cute.svg"),
            Self::Pleasing => include_str!("../docs/pet-expressions/pleasing.svg"),
            Self::Knocking => include_str!("../docs/pet-expressions/knocking.svg"),
            Self::Facepalm => include_str!("../docs/pet-expressions/facepalm.svg"),
            Self::Tongue => include_str!("../docs/pet-expressions/tongue.svg"),
        }
    }
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

        let mut names = std::collections::HashSet::new();
        for e in Expression::ALL {
            assert!(names.insert(e.name()), "duplicate expression: {}", e.name());
            assert!(!e.cn_name().is_empty());
            let e_svg = e.svg();
            assert!(e_svg.contains("<svg"));
            assert!(e_svg.len() > 500);
            assert!(
                e_svg.contains(e.cn_name()),
                "{} svg lacks its cn name",
                e.name()
            );
        }
        assert_eq!(names.len(), 12);
    }
}
