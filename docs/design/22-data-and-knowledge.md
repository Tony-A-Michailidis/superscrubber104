# 22. Data and knowledge: notebooks, datasets, knowledge bases, classic ML

> **Status: implemented** (brought forward from 1b at the owner's request). Spec: [§9](07-knowledge-bases-and-agents.md) (knowledge bases), the AI rows of [§6](04-artifact-coverage.md) (datasets, notebooks, classic ML, RAG assets). Model packages: [19](19-model-packages.md).

An AI system is more than its model. It carries the data it was tuned and evaluated on, the knowledge base it retrieves from, the notebooks it was built in, and often classic models next to the LLM. Everything here is static. Nothing is unpickled, imported, loaded by a framework or executed, and no data-science library is a dependency. SQLite files are read with the standard library, from memory, with trusted schema off.

## 22.1 Notebooks

`.ipynb` files are kind `notebook.jupyter`, with cell counts, kernel and language recorded.

| Rule | Severity | When |
|---|---|---|
| `notebook.output.saved` | low | any code cell has saved outputs (they are data; nobody reviews them as code) |
| `notebook.cell.network` | medium | a cell installs packages (`%pip install`, `!conda install`, `!npm i`, `!apt install`, ...) or downloads (`!wget`, `!curl`, `!git clone`, `!huggingface-cli download`, `!ollama pull`, ...): it needs the internet, which the high side does not have |
| `notebook.cell.shell` | low | other shell escapes (`!cmd`, `%%bash`, `%system`) |

Secrets in cells and outputs are found by the secrets scan (doc 21). Commented-out installs are not reported. Validated against a public Hugging Face example notebook, whose commented install cells and cleared outputs produce nothing.

## 22.2 Datasets

| Kind | What is read |
|---|---|
| `dataset.parquet` | the footer (Thrift compact protocol, decoded with bounds): rows, leaf columns, row groups, writer, key/value metadata keys. Every column chunk must lie in the data region (counted from the dictionary page when there is one), and row groups must add up to the footer's row count |
| `dataset.arrow` | Arrow IPC file (`ARROW1`) or stream (`save_to_disk`) |
| `dataset.jsonl`, `dataset.csv` | rows (counted up to 1 GiB), the first record's fields or the header; JSON Lines checked line by line for the first 1000 lines |
| `dataset.card` | `README.md` whose front matter has dataset keys (`dataset_info`, `configs`, `task_categories`, ...) and no model keys. The model-card reader skips these |
| `dataset.hf-state`, `-info`, `-dict` | `state.json` (the data files it lists), `dataset_info.json` (features, splits, licence), `dataset_dict.json` (splits) |
| `dataset.loading-script` | a `.py` that imports `datasets` and defines a `GeneratorBasedBuilder`/`ArrowBasedBuilder` |

**Dataset units** form around a directory holding a card, `save_to_disk` metadata or a loading script. The outermost such directory owns everything below it, so a `DatasetDict` and its splits are one unit. Data files with no such anchor keep their kind and metadata but form no unit, because nothing says they are a dataset rather than application data. Each unit is one CycloneDX `data` component.

| Rule | Severity | When |
|---|---|---|
| `dataset.file-missing` | high | a `state.json` lists a file that is absent; a `dataset_dict.json` names a split with no `state.json`; a card's `configs.data_files` pattern matches nothing |
| `dataset.file.malformed` | medium | Parquet truncated, footer outside the file, chunks outside the data region, row counts that disagree; invalid JSON lines |
| `dataset.remote-code.required` | high | a loading script (runs code under `trust_remote_code`, usually downloads the data); the URLs it names are listed |
| `licence.*` | per policy | the card's or `dataset_info.json`'s licence, through the same licence policy as models |

Validated against the public GSM8K test split (1319 rows, two columns, read correctly) and its real dataset card. Only one split was downloaded, so the configs' other splits are correctly reported missing.

## 22.3 Knowledge bases

| Store | Recognised by | What is read |
|---|---|---|
| FAISS | the index header's two `1 << 20` sentinels, whatever the file name | type code, dimension, vector count, metric, trained flag. For flat indexes the stored vector count is checked against dimension × count and the file size (truncation) |
| LangChain FAISS | `index.pkl` beside `index.faiss` | the pickled docstore is also a pickle, so the pickle checks report its imports (LangChain classes are unknown imports; loading it needs `allow_dangerous_deserialization`) |
| Chroma | `chroma.sqlite3` | collections, dimensions, distance, the embedding function's model (from `configuration_json_str`), vector count, stored documents. Opened in memory with `deserialize`, `trusted_schema=OFF`, `query_only=ON`; only Chroma's own tables are queried. HNSW segment directories (including the older pickled `index_metadata.pickle`) join the unit |
| LlamaIndex | `docstore.json`, `index_store.json`, `*vector_store.json`, `graph_store.json` | node texts; the dimension from the first stored vector |
| LanceDB, Qdrant | `*.lance` tables; `.snapshot` tar files | recognised and grouped; contents not read |

**Corpus scan.** Stored document text goes straight into a model's context when it is retrieved. Chroma documents and LlamaIndex nodes are scanned with the same detector as prompts and tool descriptions (`superscrubber104/text.py`) for instruction overrides, role reassignment, pseudo-markup aimed at the model, concealment, requests for secrets, and invisible characters. Findings name the document id. Up to 500,000 documents or 64 Mi characters are scanned per store; the rest are recorded as not assessed.

**The embedding model link.** Queries must be embedded by the model that built the index. After all units are assembled, `link_knowledge_bases` adds an `embedding-model` requirement to each knowledge base:

* a store that names its model (Chroma) must find it among the delivery's model packages, by repository or directory name. If it is missing, that is `kb.embedding-model.missing`. Chroma's `default` embedding function is reported as `all-MiniLM-L6-v2`, which Chroma would otherwise download on first use;
* a found model whose embedding dimension (from its sentence-transformers configuration) differs from the index's is `kb.embedding-model.mismatch`;
* a store that does not name its model (FAISS, LangChain, LlamaIndex) is `kb.embedding-model.unrecorded` (low), with the delivered embedding models of the right dimension listed as candidates for a reviewer to confirm.

| Rule | Severity |
|---|---|
| `kb.corpus.injection` | high |
| `kb.embedding-model.missing`, `kb.embedding-model.mismatch` | high |
| `kb.corpus.hidden-characters`, `kb.index.malformed` | medium |
| `kb.embedding-model.unrecorded` | low |

### Declared corpora

Nothing in a folder of Markdown, PDFs or Word files says that it will be fed to a model, so the delivery says so. A transfer request content entry with `unit: knowledge-base` marks its paths as a corpus:

```yaml
contents:
  - {name: policies-corpus, paths: ["rag/docs/**"], unit: knowledge-base}
```

`superscrubber104 model inspect --corpus 'rag/docs/**'` and `superscrubber104 offline-check --corpus ...` do the same without a request. Every document under a corpus path (`.md`, `.txt`, `.html`, `.json`, `.csv`, `.docx`, `.pptx`, `.xlsx`, `.odt`, `.pdf`, `.rtf`, ...), including documents inside archives there, is read the way a retrieval pipeline reads it (`superscrubber104/formats/doctext.py`) and scanned like a vector store's stored text:

| Rule | What |
|---|---|
| `kb.corpus.injection` | instructions aimed at a model, in the extracted text (HTML comments and markup included, since loaders differ in what they keep) |
| `kb.corpus.hidden-characters` | invisible characters |
| `kb.corpus.hidden-text` | constructs that hide text from a human reader: CSS `display:none`, `visibility:hidden`, zero font size or opacity, white text, off-screen positioning; Word's hidden (`w:vanish`), white and one-point text; comments and speaker notes; PDF text in the invisible rendering mode (`3 Tr`); RTF hidden text (`\v`) |

PDF text is taken from the content streams (inflated, bounded), with kerning gaps inside `TJ` arrays joined so that split words are whole again. A PDF with no extractable text (scanned images, fonts without a text map) or one that is encrypted is not assessed. Office files are read as a whole; their internal XML parts are not scanned again as separate documents. The documents form a `knowledge-base` unit (store `corpus`) rooted at the declared folder, so the request's unit check and the embedding-model link apply. Validated against a real arXiv PDF and a public Word test document.

## 22.4 Classic ML and MLflow

| Kind | Recognised by | Notes |
|---|---|---|
| `model.xgboost` | JSON beginning `{"learner":`; UBJSON `.ubj` | trees as data |
| `model.lightgbm` | text beginning `tree\nversion=v` | trees as data |
| `model.catboost` | `CBM1` magic | |
| `model.pmml` | `.pmml` with `<PMML` | |
| `model.skops` | `.skops` zip with `schema.json` | every `module.Class` it would instantiate is classified like a pickle import. Dangerous types are critical; unknown types outside `sklearn`, `numpy`, `scipy` and `builtins` are high (`model.skops.untrusted-type`). The policy's `pickle-globals` allowlist applies |
| `model.mlflow` | `MLmodel` | flavours, run id, model uuid, MLflow version. A `python_function` model with a loader module outside `mlflow.*`, a pickled `python_model` or a `code` directory is `model.mlflow.custom-code` (high). The environment files beside it (`requirements.txt`, `conda.yaml`) get the Python checks; pickled models get the pickle checks |

Each forms a model package (roles `classic-model`, `mlflow-model`) like any other model, so licences, allowlists and trust levels apply unchanged. Pickled scikit-learn, XGBoost and LightGBM models were already covered as pickles (doc 19).

## 22.5 Known limits

- **Parquet** column data is not read: values (and so PII or injected text in a fine-tuning set) are not scanned. JSON Lines and CSV are covered by the secrets scan, not by the corpus scan, because training data legitimately contains adversarial text.
- **Arrow** files are recognised but not parsed: no row count.
- **Corpus folders** are scanned only when declared (request or `--corpus`). Images in documents are not read (no OCR), so text in an image is not scanned; PDF text in fonts without a text map is not extractable.
- **LangChain docstores** are pickles: their text is not extracted, though the pickle itself is flagged.
- **Chroma** databases over 512 MiB are not opened (not assessed). **LanceDB, Qdrant, Milvus, Weaviate, pgvector and Neo4j** contents are not read.
- **Embedding model matching** is by name. A knowledge base built with a model the delivery renamed will not match; record the pairing in the transfer request.
- **MLflow** flavours other than `python_function` are recorded, not checked further; the custom-code check reads only `MLmodel`.
- Datasets on the Hugging Face hub with only remote `data_files` URLs are reported as missing files, which is what they are offline.
