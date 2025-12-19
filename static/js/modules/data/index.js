import { DNS_CONCEPTS } from './dns.js';
import { SECURITY_CONCEPTS } from './security.js';
import { CLOUD_CONCEPTS } from './cloud.js';
import { EMAIL_CONCEPTS } from './email.js';
import { NETWORKING_CONCEPTS } from './networking.js';

export const KNOWLEDGE_BASE = [
    ...SECURITY_CONCEPTS,
    ...DNS_CONCEPTS,
    ...CLOUD_CONCEPTS,
    ...EMAIL_CONCEPTS,
    ...NETWORKING_CONCEPTS
];

export {
    DNS_CONCEPTS,
    SECURITY_CONCEPTS,
    CLOUD_CONCEPTS,
    EMAIL_CONCEPTS,
    NETWORKING_CONCEPTS
};
