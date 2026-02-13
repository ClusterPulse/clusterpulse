.PHONY: generate-crd-docs docs-serve

generate-crd-docs:
	go run github.com/elastic/crd-ref-docs@v0.3.0 \
		--source-path=api/v1alpha1 \
		--config=docs/crd-ref-docs.yaml \
		--renderer=markdown \
		--output-path=docs/references/crds.md

docs-serve: generate-crd-docs
	mkdocs serve
