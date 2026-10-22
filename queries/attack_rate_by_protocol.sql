SELECT protocol_type,
       COUNT(*) AS total,
       SUM(is_attack) AS attacks,
       ROUND(100.0 * SUM(is_attack) / COUNT(*), 1) AS attack_pct
FROM connections
GROUP BY protocol_type
ORDER BY attack_pct DESC;