# Wheel runtime resources

These files are unchanged copies of the locked development checkout resources.
`tools/bundle_runtime.py` refreshes them and records each source, commit and
SHA-256 in `provenance.json`. The scanner prefers the original workspace copies
when present, and otherwise uses these copies in the installed package.

- `yara/`: kionactf/crypto-detection rules, commit
  `1b1c7bfede7133f097ed823bed64df92f4a4bc96`, Apache-2.0.
- `windriver/`: Wind-River/crypto-detector Python text engines and keyword data,
  commit `d6156a818f57826e520ca117cc3baed55f51483c`, Apache-2.0.

The full upstream LICENSE files and source copyright notices are included.
The Wind River package is imported for API/keyword search only; its archive
extraction and download interfaces are not used by QCS.
Binwalk is an optional legacy firmware fallback and is not bundled in the wheel.
