## **Tech stack**

#### FastAPi
#### Aasyncpg, postgres db
#### aiomcache, memcache
#### UV, package manager sangat cepat
- untuk menambah package, bisa dengan 
    `uv add <package>`
- untuk menghapus bisa dengan
    `uv remove <package>`
- untuk mengecek package bisa dilihat di pyproject.toml
- untuk mengubahnya bisa diubah di pyproject.toml kemudian jalankan
    `uv lock && uv sync`
---
## Simple Docs
### variable folder
pada variable terdapat hal-hal yang bersifat tersembunyi seperti password dan variable untuk environment nya


*Standarisasi response api*:

```python
response(param1, param2)
```
- `param1` : berisi pesan response misal `success`
- `param2` : berisi data tipe `Any`