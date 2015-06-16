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

--
-- Name: vote_election
--

CREATE TABLE vote_election (
    ref INTEGER PRIMARY KEY AUTOINCREMENT,
    title character varying(256),
    description text,
    period_start timestamp with time zone,
    period_stop timestamp with time zone
);

--
-- Name: vote_option
--

CREATE TABLE vote_option (
    ref INTEGER PRIMARY KEY AUTOINCREMENT,
    election_ref integer NOT NULL,
    description text,
    sort integer NOT NULL,
    option_character character(1) NOT NULL
);

--
-- Name: vote_vote
--

CREATE TABLE vote_vote (
    ref integer NOT NULL,
    voter_ref integer,
    election_ref integer NOT NULL,
    private_secret character(32),
    late_updated timestamp with time zone,
    sent_notify boolean DEFAULT 0 NOT NULL
);

--
-- Name: vote_voteoption
--

CREATE TABLE vote_voteoption (
    vote_ref integer NOT NULL,
    option_ref integer NOT NULL,
    preference integer
);
