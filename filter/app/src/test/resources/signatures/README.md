# A signature as Sokar writes it

`sokar-ed25519.sig` was made with a throwaway key that exists nowhere else:

    ssh-keygen -t ed25519 -N '' -f key
    ssh-keygen -Y sign -f key -n sokar-message m.json

OpenSSH's SSHSIG, detached, Ed25519, namespace `sokar-message`, 306 bytes - the only signature Sokar
writes. The filter checks a signature's shape and never verifies it, so this one serves beside any
test message.
