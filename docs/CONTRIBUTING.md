# Contributing to Autowasp

[![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](../issues)

We welcome contributions from developers like yourself to improve the Autowasp tool and highlight any potential problems.

## Important Resources

- [Burp Extender APIs](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/MontoyaApi.html)
- [Singapore Government Developer Portal](https://www.developer.tech.gov.sg/) - leverage on our latest technological solutions, execute your digital projects, and join our community of developers.

## How to Contribute

1. **Bug Reports**: If you find bugs, log us an [issue ticket](../issues) to report them. Do ensure that the bug has not already been reported by searching on GitHub under Issues.
2. **Questions**: Have a question but unsure who to contact, log us an [issue ticket](../issues) and we will reach out to you.
3. **Feature Requests**: Open an issue to discuss new features or improvements.

## Submitting Changes

Please send a [GitHub Pull Request to us](../pull/new/master) with a clear list of what you've done.

### Commit Messages

Always write a clear log message for your commits. We accept one-liners for small changes, but bigger changes should include changes and impact:

```bash
git commit -m "A brief summary of the commit

A paragraph describing what changed and its impact."
```

## Coding Conventions

- **Language**: We use Java for this extender.
- **APIs**: Some of the Burp extender' APIs have been overwritten in order for us to have better control of the extender’s behaviour. Refer to overwritten classes [here](../src/main/java/autowasp/http).
- **Listeners**: Please do not add additional table listener as it affects the user experience of the extender.
- **Comments**: Add a comment whenever you include a new function so that we can understand your contribution better.

Autowasp is an open-source software so bear in mind that the open-source community can read your code. Do adhere to our coding conventions and keep your codes understandable and easy to follow.
