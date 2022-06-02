CREATE TABLE "organizations" (
"id" UUID NOT NULL,
PRIMARY KEY("id"),
"nid" UUID NOT NULL,
"logo" VARCHAR (2048) NULL,
"name" VARCHAR (2048) NULL,
"slug" VARCHAR (2048) NULL,
"leads_owner" VARCHAR (2048) NULL,
"enable_qa" boolean NULL,
"is_active" boolean NULL,
"show_commission" boolean NULL,
"show_member_structure" boolean NULL,
"use_simple_lead_status" boolean NULL,
"show_level_in_dashboard" boolean NULL,
"show_shortcuts_in_dashboard" boolean NULL,
"created_at" timestamp NOT NULL,
"updated_at" timestamp NOT NULL
);