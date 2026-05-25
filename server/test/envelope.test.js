import test from 'node:test';
import assert from 'node:assert/strict';
import { checkReplay } from '../db/index.js';
import { DEFAULT_SEED } from '../../data/seed.js';
import { buildValidEnvelope, resetTestDatabase, seedReplay } from './helpers.js';
import { isTimestampValid, validateEnvelopeFields } from '../routes/validateSecure.js';

test('validateEnvelopeFields rejects missing fields', () => {
  const result = validateEnvelopeFields({ clientId: 'missing-most-fields' });
  assert.equal(result.valid, false);
  assert.match(result.message, /Missing required field/);
});

test('isTimestampValid rejects expired timestamps', () => {
  const now = Date.now();
  assert.equal(isTimestampValid(now - 10_000, 5, now), false);
  assert.equal(isTimestampValid(now + 10_000, 5, now), false);
  assert.equal(isTimestampValid(now, 5, now), true);
});

test('replay cache tracks inserted request ids', () => {
  resetTestDatabase();
  const { envelope } = buildValidEnvelope();
  seedReplay(DEFAULT_SEED.clientId, envelope.requestId);

  assert.equal(checkReplay(DEFAULT_SEED.clientId, envelope.requestId), true);
});
