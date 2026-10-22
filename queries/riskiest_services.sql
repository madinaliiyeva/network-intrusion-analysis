WITH service_stats AS (
    SELECT service,
           COUNT(*) AS total,
           SUM(is_attack) AS attacks
    FROM connections
    GROUP BY service
    HAVING COUNT(*) >= 500
)
SELECT service,
       total,
       attacks,
       ROUND(100.0 * attacks / total, 1) AS attack_pct,
       RANK() OVER (ORDER BY 1.0 * attacks / total DESC) AS risk_rank
FROM service_stats
ORDER BY risk_rank
LIMIT 10;