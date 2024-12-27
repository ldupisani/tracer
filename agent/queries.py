import duckdb

db = duckdb.connect()

print("Get sorted list of commands by average execution time")

result = db.execute("""
SELECT
    full_command,
    AVG(metric) AS average_execution_time
FROM read_parquet('metrics_stream.parquet')
WHERE type = 'EXIT'
GROUP BY full_command
ORDER BY average_execution_time DESC
""").fetchall()

for row in result:
    print(row)

print("\nGet the top 3 commands with the highest CPU time (This is in CPU milliseconds)")

result = db.execute(
"""
SELECT 
    command,
    ROUND(SUM(top_cpu_time) / (1000.0 * 60.0 * 60.0), 10) as total_cpu_time
FROM (
    SELECT 
        command, 
        pid, 
        MAX(metric) AS top_cpu_time
    FROM read_parquet('metrics_stream.parquet')
    WHERE type = 'CPU'
    GROUP BY command, pid
) subquery
GROUP BY command
ORDER BY total_cpu_time DESC
LIMIT 3
"""
).fetchall()

for row in result:
    print(row)

db.close();