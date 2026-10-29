import { config } from '@keystone-6/core';
import { lists } from './schema';

export default config({
  db: {
    provider: 'sqlite',
    url: 'file:/data/keystone.db',
  },
  // Disable the Next.js Admin UI so the container is a pure GraphQL API server
  // (faster boot, no browser build needed).
  ui: { isDisabled: true },
  server: {
    port: 3000,
  },
  lists,
});
