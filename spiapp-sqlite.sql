--
-- Name: members
--

CREATE TABLE members (
    memid INTEGER PRIMARY KEY AUTOINCREMENT,
    name character varying(50),
    email character varying(50),
    phone character varying(20),
    password character varying(15),
    pgpkey character varying(50),
    firstdate date,
    expirydate date,
    ismember boolean DEFAULT 0 NOT NULL,
    iscontrib boolean DEFAULT 0 NOT NULL,
    ismanager boolean DEFAULT 0 NOT NULL,
    sub_private boolean DEFAULT 0,
    lastactive date
);

--
-- Name: applications
--

CREATE TABLE applications (
    appid INTEGER PRIMARY KEY AUTOINCREMENT,
    appdate date,
    member integer,
    emailkey character varying(50),
    emailkey_date date,
    validemail boolean,
    validemail_date date,
    contrib text,
    comment text,
    lastchange date,
    manager integer,
    manager_date date,
    approve boolean,
    approve_date date,
    contribapp boolean DEFAULT 0
);
