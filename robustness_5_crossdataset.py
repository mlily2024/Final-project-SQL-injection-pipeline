#!/usr/bin/env python3
"""
Robustness test 5/7: out-of-distribution (cross-distribution) generalisation.

Robustness that only holds in-distribution is weak. We evaluate both models on a
curated set that is deliberately different from the training dataset: canonical
SQL injection payloads drawn from the standard attack techniques (union-based,
boolean and time-based blind, error-based, stacked queries, and classic
WAF-bypass forms), together with legitimate SQL and benign text. We report the
detection rate (recall on the attacks) and the false-positive rate (on benign)
for each model on this novel distribution.
"""
import os
import numpy as np
import robustness_common as rc

OUT_MD = os.path.join(rc.HERE, "results", "robustness_crossdataset.md")

MALICIOUS = [
    "' or 1=1--", "' or '1'='1", "admin'--", "' or 1=1#", "') or ('1'='1",
    "' union select null,username,password from users--",
    "1 union all select 1,2,3,4,5,6,7,8,9,10--",
    "' union select @@version--", "-1' union select database(),user()--",
    "1' and 1=convert(int,(select @@version))--",
    "' and extractvalue(1,concat(0x7e,version()))--",
    "' and updatexml(1,concat(0x7e,(select version())),1)--",
    "1' waitfor delay '0:0:5'--", "' or sleep(5)#", "1 and (select sleep(5))",
    "'; drop table users;--", "1'; exec xp_cmdshell('whoami')--",
    "1); drop table logs;--", "' or username like '%admin%'--",
    "1 procedure analyse(extractvalue(1,concat(0x3a,version())),1)",
    "' union select 1,2,load_file('/etc/passwd')--",
    "' or 1=1 limit 1 offset 0--", "1' group by columnnames having 1=1--",
    "' unioN sELeCt 1,2,3--", "1/**/union/**/select/**/1,2,3--",
    "%27%20or%201%3d1--", "' or 0x50=0x50--", "1' or 'a'='a",
    "'||(select user())||'", "'+(select top 1 name from sysobjects)+'",
    "1' and substring(@@version,1,1)='5'--", "' or exists(select * from users)--",
    "'; begin declare @x int; end--", "1 or 1=1", "' having 1=1--",
]
BENIGN = [
    "select * from products where id = 42", "SELECT name, price FROM catalogue WHERE category = 'books'",
    "update users set last_login = now() where user_id = 7",
    "insert into orders (customer, total) values ('alice', 29.99)",
    "delete from cart where session = 'abc123'", "select count(*) from visits where day = '2024-05-01'",
    "john.doe@example.com", "my order number is 12345", "search: blue running shoes size 10",
    "the quick brown fox jumps over the lazy dog", "please reset my password", "2024-05-14T10:30:00",
    "SELECT first_name, last_name FROM employees ORDER BY hire_date DESC",
    "select p.name, c.title from products p join categories c on p.cat_id = c.id",
    "update inventory set qty = qty - 1 where sku = 'ABC-123'", "hello world", "invoice #INV-2024-0042",
    "contact us at support@shop.example.com", "London, United Kingdom", "temperature is 21 degrees",
    "select * from bookings where checkin between '2024-06-01' and '2024-06-07'",
    "add 3 items to the basket", "the meeting is at 3pm on tuesday",
    "insert into feedback (rating, comment) values (5, 'great service')",
    "user profile updated successfully", "select avg(price) from listings where region = 'north'",
    "my name is o'brien", "select id, email from subscribers where active = true",
    "product code: XZ-9981", "order confirmed, thank you for shopping",
    "grant select on reports to analyst_role", "show me my recent transactions",
    "select title from articles where published = 1 and author = 'smith'", "café latte and a croissant",
]

queries = MALICIOUS + BENIGN
y = np.array([1] * len(MALICIOUS) + [0] * len(BENIGN))

gnn, mlp, mlp_t, bp = rc.load_models()
cls, graphs = rc.embed_and_graph(queries, label=1)
gp = rc.gnn_predict(gnn, graphs); pb = mlp.predict(cls)

def report(name, pred):
    mal = (y == 1); ben = (y == 0)
    recall = (pred[mal] == 1).mean() * 100          # attack detection rate
    fpr = (pred[ben] == 1).mean() * 100             # false-alarm rate
    acc = (pred == y).mean() * 100
    return recall, fpr, acc, int((pred[mal] == 0).sum()), int((pred[ben] == 1).sum())

gr = report("structure-GNN", gp); br = report("BERT-only", pb)
print(f"OOD set: {len(MALICIOUS)} attacks, {len(BENIGN)} benign")
print(f"  structure-GNN  detection {gr[0]:.1f}%  FPR {gr[1]:.1f}%  acc {gr[2]:.1f}%  (missed {gr[3]}, false-alarms {gr[4]})")
print(f"  BERT-only      detection {br[0]:.1f}%  FPR {br[1]:.1f}%  acc {br[2]:.1f}%  (missed {br[3]}, false-alarms {br[4]})")

lines = ["# Robustness test 5: out-of-distribution generalisation", "",
         f"Evaluation on a curated set that is deliberately different from the training dataset: "
         f"{len(MALICIOUS)} canonical SQL injection payloads (union-based, boolean and time-based "
         f"blind, error-based, stacked, and classic WAF-bypass forms) and {len(BENIGN)} legitimate "
         "SQL statements and benign text. This tests generalisation to a novel distribution.", "",
         "| Model | Attack detection (%) | False-positive rate (%) | Accuracy (%) | Missed / false-alarms |",
         "|---|---|---|---|---|",
         f"| Structure-aware BERT-GNN | {gr[0]:.1f} | {gr[1]:.1f} | {gr[2]:.1f} | {gr[3]} / {gr[4]} |",
         f"| BERT-only (MLP) | {br[0]:.1f} | {br[1]:.1f} | {br[2]:.1f} | {br[3]} / {br[4]} |", "",
         "Both models are trained only on the original dataset, so this measures how well the "
         "learned detector transfers to attack and benign patterns it was not trained on. "
         "Reproduce with `python robustness_5_crossdataset.py`.", ""]
os.makedirs(os.path.dirname(OUT_MD), exist_ok=True); open(OUT_MD, "w", encoding="utf-8").write("\n".join(lines))
print("wrote", OUT_MD)
