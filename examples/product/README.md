# Product VC example

`product.jsonld` is the product supplied in the project conversation, originally
illustrated in the future-of-data-sharing ExampleHolon page. Its values are
preserved. `context.jsonld` contains the Holon extension and scoped Schema.org
term mappings from https://schema.org/docs/jsonldcontext.json (2026-09-28), plus
the supplied GS1 prefix. It preserves the upstream HTTP Schema.org namespace.

The full and disclosure schemas validate this example's subject shape. They are
not official GS1 schemas. `reveal.json` selects identity, ingredients and allergens.

Run `python3 scripts/product-workflow.py --output /tmp/holon-product-example`
after `cargo build --locked --release`. This creates fresh, actual signatures;
no expiring signed fixture or private key is committed here. See
`docs/PRODUCT_EXAMPLE.md` for the complete workflow and deployment limitations.
