# Phishing Message Detector

A small, rule-based Python tool that checks a message for common phishing signs: urgency, requests for sensitive information, generic greetings, and suspicious links.

It runs entirely on your computer. It does not visit any link or send your text anywhere.

This is a learning project. It does not replace real security software, and a message with no warnings can still be a scam.

## What it checks

- **Urgency:** phrases such as "urgent", "within 24 hours", or "your account will be suspended".
- **Sensitive requests:** asks for passwords, verification codes, card numbers, or bank details.
- **Generic greetings:** "Dear customer" instead of your name.
- **Links:**
  - plain HTTP instead of HTTPS
  - `@` inside a URL, which can hide the real destination
  - raw IP addresses instead of domain names
  - URL shorteners that hide the destination

## Requirements

- Python 3.8 or newer. No external packages are needed.

## Usage

Pass the message as an argument:

```bash
python phishing_detector.py "URGENT: your account will be suspended. Send your password within 24 hours."
```

Or pipe a message from a file:

```bash
cat message.txt | python phishing_detector.py
```

Example output:

```
Risk level: High (score 6)
- Creates urgency or threatens account closure
- Asks for sensitive information
...
```

## Running the tests

```bash
python -m unittest test_phishing_detector.py -v
```

## How the score works

Each rule adds points, and the total sets the risk level:

| Score | Risk level |
| ----- | ---------- |
| 0     | None detected |
| 1-2   | Low |
| 3-4   | Medium |
| 5 or more | High |

## Ideas for improvement

- Detect lookalike domains, such as `paypa1.com` instead of `paypal.com`.
- Add more languages.
- Read `.eml` email files directly.

## References

For more detailed explanations of phishing and online security: https://mysafeip.blogspot.com/

## License

MIT. See [LICENSE](LICENSE).
