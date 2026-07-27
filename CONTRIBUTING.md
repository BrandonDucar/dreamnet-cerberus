# Contributing

Contributions are welcome when they preserve the airlock's core properties:

- no target dependency installation
- no execution of target code
- no network requirement for the static scan
- deterministic findings
- bounded file and byte traversal
- no matched payload text in receipts
- tests for both malicious and benign behavior

Before opening a pull request:

```bash
npm test
node scripts/cerberus.mjs gate . \
  --source=https://github.com/BrandonDucar/dreamnet-cerberus \
  --source-identity=BrandonDucar/dreamnet-cerberus \
  --commit=0123456789abcdef0123456789abcdef01234567 \
  --allow=green,yellow \
  --no-write
```

New detection rules should include a hostile fixture and a nearby negative
control. Explain expected false positives and why the severity is appropriate.
