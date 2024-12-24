import duckdb

db = duckdb.connect()

# Verify the data by reading it back
result = db.execute("""
    SELECT count(*)
    FROM read_parquet('metrics_stream.parquet')
    WHERE type = 'EXIT'
""").fetchall()

# result = db.execute("""
#     SELECT * 
#     FROM read_parquet('metrics_stream.parquet')
#     WHERE type = 'EXIT'
#     ORDER BY metric DESC
# """).fetchall()

for row in result:
    print(row)


db.close();