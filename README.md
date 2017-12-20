# batch-exec-mysql-sql
批量执行mysql命令

```
[root@storm1 batch-exec-mysql-sql]# python batch_exec_sql.py --help
usage: batch_exec_sql.py [-h] [--host-port [host:port]] [--host-file host]
                         --sql sql

Usage Example: 
python batch_exec_sql.py --host-port="127.0.0.1:3306" --sql="show slave status"
python batch_exec_sql.py --host-port="127.0.0.1:3306" --host-port="127.0.0.1:3306" --sql="show slave status"
python batch_exec_sql.py --host-file="ip.txt" --sql="show master status"

Description:
    Check the DRC mode, table need fields
    

optional arguments:
  -h, --help            show this help message and exit
  --host-port [host:port]
                        --host-ports can use multiple times
  --host-file host      host:port in file and every line
  --sql sql             sql
```
