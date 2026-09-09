-- The MySQL mirror of seed.sql. Same shape, MySQL types.
CREATE TABLE customers (
  id     int AUTO_INCREMENT PRIMARY KEY,
  name   varchar(64),
  region varchar(16),
  email  varchar(64)
);

CREATE TABLE orders (
  id          int AUTO_INCREMENT PRIMARY KEY,
  customer_id int,
  status      varchar(16),
  total       decimal(10, 2),
  INDEX (customer_id)
);

CREATE TABLE inventory (
  sku       varchar(32) PRIMARY KEY,
  qty       int,
  warehouse varchar(16)
);

-- MySQL has no generate_series, so build the rows from a recursive CTE.
INSERT INTO customers (name, region, email)
WITH RECURSIVE s (i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM s WHERE i < 500)
SELECT CONCAT('cust ', i),
       ELT(1 + i % 3, 'emea', 'apac', 'namer'),
       CONCAT('c', i, '@example.com')
FROM s;

INSERT INTO orders (customer_id, status, total)
WITH RECURSIVE s (i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM s WHERE i < 5000)
SELECT 1 + (i % 500), ELT(1 + i % 3, 'pending', 'shipped', 'cancelled'), RAND() * 400
FROM s;

INSERT INTO inventory
WITH RECURSIVE s (i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM s WHERE i < 2000)
SELECT CONCAT('sku-', i), RAND() * 100, ELT(1 + i % 3, 'ams', 'sfo', 'sin')
FROM s;
