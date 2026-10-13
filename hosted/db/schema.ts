import {sqliteTable,text,integer,index} from 'drizzle-orm/sqlite-core';
export const sandboxes=sqliteTable('relay_sandboxes',{id:text('id').primaryKey(),revision:integer('revision').notNull(),expires:integer('expires').notNull(),data:text('data').notNull()},table=>[index('relay_sandbox_expiry').on(table.expires)]);
