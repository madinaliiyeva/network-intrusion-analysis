SELECT category,
       COUNT(*) AS total,
       SUM(CASE WHEN flag = 'S0' THEN 1 ELSE 0 END) AS unanswered_syn,
       ROUND(100.0 * SUM(CASE WHEN flag = 'S0' THEN 1 ELSE 0 END) / COUNT(*), 1) AS unanswered_pct
FROM connections
GROUP BY category
ORDER BY unanswered_pct DESC;