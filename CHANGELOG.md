# Changelog
- 2.0.0
  - **BREAKING CHANGE:** Changed run order of scripts to run user scripts first and system scripts after. This enables
    the possibility of uninstalling pam-duress as a system level operation.
  - Linted with clang-tidy. No linter errors in files.
  - Changed outputs of errno to strerror(errno).
  - General spelling pass.
  - 20220404 - DOC ONLY UPDATE: Added Arch Linux Documentation
- 1.1.7
  - Removal of exit statements; replaced with NULL to prevent the PAM application exiting. Contribution by
    [Jürgen Hötzel on github](https://github.com/juergenhoetzel).
- 1.1.6
  - Removal of unnecessary intermediate shell. Contribution by
    [Jürgen Hötzel on github](https://github.com/juergenhoetzel).
  - Debug builds will not redirect output of stderr and stdout to /dev/null by default to support testing/debugging.
- 1.1.5
  - Makefile improvements by [Prateek Ganguli on github](https://github.com/pganguli). Debug build path now added.
- 1.1.4
  - Memory leak resolved by [Jürgen Hötzel on github](https://github.com/juergenhoetzel).
- 1.1.3
  - Fixed privilege escalation issue #16 [reported by wowaname](https://news.ycombinator.com/item?id=28276200) from
    Hacker News.
  - Redirected output of all scripts/binaries to /dev/null by convention.
- 1.1.2
  - Fixed issue #11; error when running scripts under /etc/duress.d resulting in account unavailable error.
  - Fixed issue #10; documentation or pushover script.
  - Added link to demo video.
  - Removed unnecessary casts for malloc calls.
  - Created dbg_log wrapper function to clean up DEBUG compile flag use.
- 1.1.1
  - OSX support and makefile improvements contributed by [cormacrelf](https://github.com/cormacrelf).
- 1.1.0
  - Fixed privilege escalation vulnerability that could allow an unprivileged user to run commands as root.
- 1.0.1
  - Fixed some potential memory leaks, linted, and adjusted documentation.
- 1.0.0
  - Initial commit of prototype tested on Debian 10.
