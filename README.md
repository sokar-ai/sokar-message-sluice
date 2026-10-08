# sokar-message-sluice

<img src="doc/images/early-bird.svg" width="350" alt="Early bird - work in progress">

> **Early bird - work in progress.** Sokar is not stable yet: until release 1.0.0, its code, commands
> and file formats can change without notice.

The filter that every message an AI agent sends under Sokar passes through. It lets plain English
prose through and refuses a message that carries data instead: an encoded payload, a file in a
message part, a link or data part where text belongs.

It is an **egress filter**: it stops an agent from sending data out, whether by accident or because
a prompt injection told it to. Sokar also runs it over messages that arrive from a peer it does not
vouch for.

**The documentation:** <https://sokar-ai.github.io/sluice/> - what it refuses and what it does not
catch, where it sits, how it reads a message, and why it is built that way.

**There is no language model inside it.** Fixed rules, the same verdict every time for the same
message, and every refusal names the rule that made it. A checker built on a model could be talked
round by the same text it is checking.

## Modules

[`filter`](filter/README.md) - the filter's code and its packages, the only module here. It is not
a transport: what carries a message that passed lives in a repository of its own, such as
`sokar-message-matrix`.

## Build

```
./mvnw -B -s settings.xml verify                                   # the code and its tests
JAVA_HOME=<graalvm> ./mvnw -B -s settings.xml -Pnative,dist verify # native executable and packages
```

Java 25. More in [`build.md`](https://github.com/sokar-ai/sokar-message-sluice/blob/main/build.md).

## License

GPL-3.0-or-later, as the rest of Sokar.
