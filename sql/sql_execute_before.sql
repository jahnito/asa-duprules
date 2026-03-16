CREATE TABLE "upper_rules" (
	"id"	INTEGER,
	"zone"	TEXT NOT NULL,
	"num_line"	TEXT NOT NULL,
	"rule"	TEXT NOT NULL,
	"obj_gr_serv"	TEXT,
	"proto_l3"	TEXT,
	"proto_l4"	TEXT,
	"obj_gr_src"	TEXT,
	"host_src"	TEXT,
	"any_src"	TEXT,
	"object_src"	TEXT,
	"prefix_src"	TEXT,
	"obj_gr_dst"	TEXT,
	"host_dst"	TEXT,
	"any_dst"	BLOB,
	"object_dst"	TEXT,
	"proto_port"	TEXT,
	"proto_ports"	TEXT,
	"prefix_dst"	TEXT,
	"inactive"	TEXT,
	"hit_count"	TEXT,
	"original_line"	TEXT,
	PRIMARY KEY("id" AUTOINCREMENT)
);

CREATE TABLE "rules" (
	"id"	INTEGER,
	"zone"	TEXT NOT NULL,
	"num_line"	TEXT NOT NULL,
	"rule"	TEXT NOT NULL,
	"proto_l3"	TEXT,
	"proto_l4"	TEXT,
	"proto_num"	TEXT,
	"host_src"	TEXT,
	"prefix_src"	TEXT,
	"any_src"	TEXT,
	"host_dst"	TEXT,
	"prefix_dst"	TEXT,
	"any_dst"	TEXT,
	"proto_port"	TEXT,
	"proto_ports"	TEXT,
	"inactive"	TEXT,
	"hit_count"	TEXT,
	"original_line"	TEXT,
	PRIMARY KEY("id" AUTOINCREMENT)
);

-- Таблица объектов --
CREATE TABLE "asa_objects" (
	"id"	INTEGER,
	"name"	TEXT,
	"obj_type"	TEXT,
	"description"	TEXT,
	PRIMARY KEY("id" AUTOINCREMENT)
);

-- Таблица хостов --
CREATE TABLE "asa_obj_hosts" (
	"id"	INTEGER,
	"host"	TEXT,
	"asa_object"	INTEGER,
	FOREIGN KEY("asa_object") REFERENCES "asa_objects"("id") ON DELETE CASCADE,
	PRIMARY KEY("id" AUTOINCREMENT)
);


-- Таблица префиксов --
CREATE TABLE "asa_obj_subnets" (
	"id"	INTEGER,
	"subnet"	TEXT,
	"asa_object"	INTEGER,
	FOREIGN KEY("asa_object") REFERENCES "asa_objects"("id") ON DELETE CASCADE,
	PRIMARY KEY("id" AUTOINCREMENT)
);

-- Таблица вложенных объектов --
CREATE TABLE "asa_obj_objects" (
	"id"	INTEGER,
	"object"	TEXT,
	"asa_object"	INTEGER,
	FOREIGN KEY("asa_object") REFERENCES "asa_objects"("id") ON DELETE CASCADE,
	PRIMARY KEY("id" AUTOINCREMENT)
);

-- Таблица вложенных групп --
CREATE TABLE "asa_obj_groups" (
	"id"	INTEGER,
	"group"	TEXT,
	"asa_object"	INTEGER,
	PRIMARY KEY("id" AUTOINCREMENT),
	FOREIGN KEY("asa_object") REFERENCES "asa_objects"("id") ON DELETE CASCADE
);
