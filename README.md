# LDAPSync

Unidirectional synchronization of users from a source to a target LDAP

## Installation

```
git clone https://github.com/4teamwork/ldapsync
cd ldapsync
python3.7 -m venv .
. bin/activate
pip install -e . -c versions.txt
```

## Configuration

```
cp ldapsync.example.yaml ldapsync.yaml
```

Provide details for source and target LDAP in `ldapsync.yaml`.

## Run Synchronization

```
ldapsync -c ldapsync.yaml
```
