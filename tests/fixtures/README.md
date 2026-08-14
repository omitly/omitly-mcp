# Test fixtures

## `sample.pdf`

A small two-page PDF used to exercise the detection and redaction tool paths.

It deliberately contains strings that **look** like sensitive data, because a
detector that is only ever tested on placeholder text like `XXX-XX-XXXX` is not
being tested at all — the patterns, checksums and word boundaries only get
exercised by values with the right shape.

**Every value in it is a published, standard test value. None of it is real,
and none of it belongs to anybody.**

| Value in the fixture | What it is |
| --- | --- |
| `123-45-6789` | The canonical example SSN. The US Social Security Administration has never issued a number beginning `123-45`, and this specific value appears throughout its own published material. |
| `4111 1111 1111 1111` | The standard Visa test card number. It satisfies the Luhn check — which is the point, since the detector validates checksums — but is not a real account and is refused by every payment processor. |
| `jane.doe@example.com` | `example.com` is reserved for documentation by RFC 2606 and cannot be registered. |
| `$4,250,000` settlement figure, "Lacuna Test Document" | Invented for this fixture. |

If you are adding a new fixture, keep to that standard: use values that are
published as test data (the reserved ranges above, or a documented DLP test-data
source such as dlptest.com), and record here what each one is and why it is
safe. Never use a real document, and never use a value you cannot cite a public
source for.

## Why this file exists

So that a reader who finds an SSN-shaped string in a public repository can
confirm in a few seconds that it is a test value, rather than having to
recognise each constant on sight or assume the worst.
