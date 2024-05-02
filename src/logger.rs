//! Logging facility that is lightweight and supports the key-value feature of the [`log`] crate.

use std::io::Write;

use anstyle::{AnsiColor, Color, Style};
use anyhow::{Context, Result};
use log::{
    kv::{self, Key, Value, VisitSource, VisitValue},
    LevelFilter, Log,
};
use time::{OffsetDateTime, UtcOffset};

/// Initialize the logger.
///
/// Should be called at the start of the application, and will never fail in that case.
///
/// # Errors
///
/// Will return an `Err` if another logger instance has been set with [`log::set_boxed_logger`]
/// already.
pub fn init() -> Result<()> {
    let offset = UtcOffset::current_local_offset().context("failed determining local offset")?;

    log::set_max_level(LevelFilter::Trace);
    log::set_boxed_logger(Box::new(Logger { offset })).map_err(Into::into)
}

struct Logger {
    offset: UtcOffset,
}

const NAMES: &[&str] = &[env!("CARGO_CRATE_NAME")];
const PREFIXES: &[&str] = &[concat!(env!("CARGO_CRATE_NAME"), "::")];

impl Log for Logger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        let target = metadata.target();

        NAMES.iter().any(|name| target == *name)
            || PREFIXES.iter().any(|prefix| target.starts_with(prefix))
    }

    fn log(&self, record: &log::Record<'_>) {
        static BRACKET_STYLE: Style = Style::new().dimmed();
        static TARGET_STYLE: Style = Style::new().bold();
        static TIME_STYLE: Style = Style::new().dimmed();

        if !self.enabled(record.metadata()) {
            return;
        }

        let (lvl, lvl_style) = match record.level() {
            log::Level::Error => ("ERROR", AnsiColor::Red),
            log::Level::Warn => ("WARN", AnsiColor::Yellow),
            log::Level::Info => ("INFO", AnsiColor::Green),
            log::Level::Debug => ("DEBUG", AnsiColor::Blue),
            log::Level::Trace => ("TRACE", AnsiColor::Magenta),
        };
        let lvl_style = lvl_style.on_default();

        let mut out = anstream::stderr().lock();
        let time = OffsetDateTime::now_utc().to_offset(self.offset);

        let _ = write!(
            &mut out,
            "{time} {open_bracket}{level}{close_bracket} {target}: {args}",
            time = format_args!(
                "{TIME_STYLE}{:02}:{:02}:{:02}.{:03}{TIME_STYLE:#}",
                time.hour(),
                time.minute(),
                time.second(),
                time.millisecond(),
            ),
            open_bracket = format_args!("{BRACKET_STYLE}[{BRACKET_STYLE:#}"),
            close_bracket = format_args!("{BRACKET_STYLE}]{BRACKET_STYLE:#}"),
            level = format_args!("{lvl_style}{lvl:5}{lvl_style:#}"),
            target = format_args!("{TARGET_STYLE}{}{TARGET_STYLE:#}", record.target()),
            args = record.args(),
        );

        let _ = record.key_values().visit(&mut Visitor(&mut out));
        let _ = writeln!(&mut out);
    }

    fn flush(&self) {}
}

struct Visitor<'a, T>(&'a mut T);

impl<T: Write> VisitSource<'_> for Visitor<'_, T> {
    fn visit_pair(&mut self, key: Key<'_>, value: Value<'_>) -> Result<(), kv::Error> {
        static STYLE: Style = Style::new()
            .fg_color(Some(Color::Ansi(AnsiColor::Blue)))
            .italic();

        write!(self.0, " {STYLE}{key}{STYLE:#}=")?;
        value.visit(self)
    }
}

static NUMBER_STYLE: Style = Style::new().fg_color(Some(Color::Ansi(AnsiColor::Yellow)));
static STRING_STYLE: Style = Style::new().fg_color(Some(Color::Ansi(AnsiColor::Green)));
static ERROR_STYLE: Style = Style::new().fg_color(Some(Color::Ansi(AnsiColor::Red)));

impl<T: Write> VisitValue<'_> for Visitor<'_, T> {
    fn visit_any(&mut self, value: Value<'_>) -> Result<(), kv::Error> {
        write!(self.0, "{value}").map_err(Into::into)
    }

    fn visit_null(&mut self) -> Result<(), kv::Error> {
        static STYLE: Style = Style::new().dimmed();

        write!(self.0, "{STYLE}<null>{STYLE:#}").map_err(Into::into)
    }

    fn visit_u64(&mut self, value: u64) -> Result<(), kv::Error> {
        write!(self.0, "{NUMBER_STYLE}{value}{NUMBER_STYLE:#}").map_err(Into::into)
    }

    fn visit_i64(&mut self, value: i64) -> Result<(), kv::Error> {
        write!(self.0, "{NUMBER_STYLE}{value}{NUMBER_STYLE:#}").map_err(Into::into)
    }

    fn visit_u128(&mut self, value: u128) -> Result<(), kv::Error> {
        write!(self.0, "{NUMBER_STYLE}{value}{NUMBER_STYLE:#}").map_err(Into::into)
    }

    fn visit_i128(&mut self, value: i128) -> Result<(), kv::Error> {
        write!(self.0, "{NUMBER_STYLE}{value}{NUMBER_STYLE:#}").map_err(Into::into)
    }

    fn visit_f64(&mut self, value: f64) -> Result<(), kv::Error> {
        write!(self.0, "{NUMBER_STYLE}{value}{NUMBER_STYLE:#}").map_err(Into::into)
    }

    fn visit_bool(&mut self, value: bool) -> Result<(), kv::Error> {
        static STYLE: Style = Style::new().fg_color(Some(Color::Ansi(AnsiColor::Magenta)));

        write!(self.0, "{STYLE}{value}{STYLE:#}").map_err(Into::into)
    }

    fn visit_str(&mut self, value: &str) -> Result<(), kv::Error> {
        write!(self.0, "{STRING_STYLE}{value}{STRING_STYLE:#}").map_err(Into::into)
    }

    fn visit_borrowed_str(&mut self, value: &'_ str) -> Result<(), kv::Error> {
        write!(self.0, "{STRING_STYLE}{value}{STRING_STYLE:#}").map_err(Into::into)
    }

    fn visit_char(&mut self, value: char) -> Result<(), kv::Error> {
        write!(self.0, "{STRING_STYLE}{value}{STRING_STYLE:#}").map_err(Into::into)
    }

    fn visit_error(
        &mut self,
        mut err: &(dyn std::error::Error + 'static),
    ) -> Result<(), kv::Error> {
        write!(self.0, "{ERROR_STYLE}{err:#?}")?;

        while let Some(source) = err.source() {
            write!(self.0, "\n\t{source:#?}")?;
            err = source;
        }

        write!(self.0, "{ERROR_STYLE:#}").map_err(Into::into)
    }

    fn visit_borrowed_error(
        &mut self,
        mut err: &'_ (dyn std::error::Error + 'static),
    ) -> Result<(), kv::Error> {
        write!(self.0, "{ERROR_STYLE}{err:#?}")?;

        while let Some(source) = err.source() {
            write!(self.0, "\n\t{source:#?}")?;
            err = source;
        }

        write!(self.0, "{ERROR_STYLE:#}").map_err(Into::into)
    }
}
