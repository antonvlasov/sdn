CREATE TABLE timings(
    random_id TEXT NOT NULL,
    host_service TEXT NOT NULL,
    iteration_number INTEGER NOT NULL,
    start_time INTEGER NOT NULL,
    end_time INTEGER NOT NULL
);

INSERT INTO timings(random_id,host_service, iteration_number, start_time, end_time)
VALUES('1','server-1','0','1','2');

SELECT host_service,start_time,end_time FROM timings
WHERE iteration_number=1;