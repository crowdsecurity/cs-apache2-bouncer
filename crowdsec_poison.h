/* Functions this module does not use, made compile errors.
 *
 * Include this LAST in a .c file, after every other header: the pragma would
 * otherwise reject the system headers that legitimately declare these.
 *
 * The replacements all come from APR and take a pool, so a buffer cannot be
 * overrun by construction:
 *
 *   strcpy, strcat, strncpy, strncat  -> apr_pstrcat, apr_cpystrn
 *   sprintf, vsprintf                 -> apr_psprintf, apr_snprintf
 *   atoi, atol, atof                  -> apr_strtoff, crowdsec_parse_size
 *   strtok                            -> apr_strtok
 *   alloca                            -> apr_palloc
 *   gets                              -> nothing; never appropriate
 *
 * atoi is in the list for a specific reason: it cannot distinguish "0" from
 * "banana", and a directive that silently read a typo as zero used to mean OK,
 * which Apache spells as "allow".
 */
#ifndef CROWDSEC_POISON_H
#define CROWDSEC_POISON_H

#if defined(__GNUC__) || defined(__clang__)
/* glibc defines alloca as a macro, and an existing macro cannot be poisoned. */
#ifdef alloca
#undef alloca
#endif
#pragma GCC poison strcpy strcat strncpy strncat sprintf vsprintf gets \
                   strtok atoi atol atof alloca
#endif

#endif /* CROWDSEC_POISON_H */
