-- Demo schema for sqlsnoop. Small enough to seed in a second, large enough
-- that the N+1 in demo/workload.py has real rows to iterate and the join
-- takes measurable time.
CREATE TABLE customers (
  id     serial PRIMARY KEY,
  name   text,
  region text,
  email  text
);

CREATE TABLE orders (
  id          serial PRIMARY KEY,
  customer_id int,
  status      text,
  total       numeric,
  created_at  timestamptz DEFAULT now()
);

CREATE TABLE inventory (
  sku       text PRIMARY KEY,
  qty       int,
  warehouse text
);

INSERT INTO customers (name, region, email)
SELECT 'cust ' || i,
       (ARRAY['emea', 'apac', 'namer'])[1 + i % 3],
       'c' || i || '@example.com'
FROM generate_series(1, 500) i;

INSERT INTO orders (customer_id, status, total)
SELECT 1 + (i % 500),
       (ARRAY['pending', 'shipped', 'cancelled'])[1 + i % 3],
       (random() * 400)::numeric(10, 2)
FROM generate_series(1, 5000) i;

INSERT INTO inventory
SELECT 'sku-' || i,
       (random() * 100)::int,
       (ARRAY['ams', 'sfo', 'sin'])[1 + i % 3]
FROM generate_series(1, 2000) i;

-- The N+1's lookup is indexed on purpose. The point of the demo is that an
-- N+1 hurts even when every individual query is fast and correctly indexed —
-- 84 fast queries still cost more than one join.
CREATE INDEX ON orders (customer_id);
