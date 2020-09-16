--
-- Name: members
--

CREATE SEQUENCE members_memid_seq;
CREATE TABLE members (
    memid INTEGER PRIMARY KEY DEFAULT nextval('members_memid_seq'),
    name character varying(50),
    email character varying(50),
    phone character varying(20),
    password character varying(15),
    pgpkey character varying(50),
    firstdate date,
    expirydate date,
    ismember boolean DEFAULT FALSE NOT NULL,
    iscontrib boolean DEFAULT FALSE NOT NULL,
    ismanager boolean DEFAULT FALSE NOT NULL,
    createvote boolean DEFAULT FALSE NOT NULL,
    sub_private boolean DEFAULT FALSE,
    lastactive date
);
ALTER SEQUENCE members_memid_seq OWNED BY members.memid;

--
-- Name: applications
--

CREATE SEQUENCE applications_appid_seq;
CREATE TABLE applications (
    appid INTEGER PRIMARY KEY DEFAULT nextval('applications_appid_seq'),
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
    contribapp boolean DEFAULT FALSE
);
ALTER SEQUENCE applications_appid_seq OWNED BY applications.appid;

--
-- Name: vote_election
--

CREATE SEQUENCE vote_election_ref_seq;
CREATE TABLE vote_election (
    ref INTEGER PRIMARY KEY DEFAULT nextval('vote_election_ref_seq'),
    title character varying(256) NOT NULL,
    description text,
    period_start timestamp with time zone,
    period_stop timestamp with time zone,
    owner integer NOT NULL,
    winners integer DEFAULT 1 NOT NULL,
    system integer NOT NULL
);
ALTER SEQUENCE vote_election_ref_seq OWNED BY vote_election.ref;

--
-- Name: vote_option
--

CREATE SEQUENCE vote_option_ref_seq;
CREATE TABLE vote_option (
    ref INTEGER PRIMARY KEY DEFAULT nextval('vote_option_ref_seq'),
    election_ref integer NOT NULL,
    description text,
    sort integer NOT NULL,
    option_character character(1) NOT NULL
);
ALTER SEQUENCE vote_option_ref_seq OWNED BY vote_option.ref;

--
-- Name: vote_vote
--

CREATE TABLE vote_vote (
    ref integer NOT NULL,
    voter_ref integer,
    election_ref integer NOT NULL,
    private_secret character(32),
    late_updated timestamp with time zone,
    sent_notify boolean DEFAULT FALSE NOT NULL
);

--
-- Name: vote_voteoption
--

CREATE TABLE vote_voteoption (
    vote_ref integer NOT NULL,
    option_ref integer NOT NULL,
    preference integer
);
