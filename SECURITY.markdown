# Security-critical bug reporting policy

For "security-critical" bugs we have a dedicated bug-reporting process that
is distinct from the main project's Github issue tracker.  Here, we define a
bug as "security critical" if:

1. The bug can be used to disclose confidential data provisioned into a
   Veracruz instance by a principal in a computation to another principal,
2. This flow of information is not explicitly allowed by the global policy
   of a particular Veracruz computation, or could be used to undermine any
   Veracruz computation independent of the particular global policy in force,
3. Is not explicitly outside of the Veracruz threat-model, as discussed in
   the Veracruz project's Frequently Asked Questions document, available from
   the Veracruz homepage.

If you believe that you have found a bug in the Veracruz code-base that
satisfies all of the conditions above, then please report the issue discreetly
and directly to the Veracruz development team, using the dedicated e-mail
alias: veracruz-project@arm.com.  Once reported, a member of the development
team will engage with you to further understand the bug and work on developing
a fix for the issue.
