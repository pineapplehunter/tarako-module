state=$1
measured=$2

# Use a private ext4 filesystem without changing the VM's root filesystem.
mkdir -p "$measured"
truncate -s 128M "$state/verity.img"
mkfs.ext4 -q -F -O verity "$state/verity.img"
mount -o loop "$state/verity.img" "$measured"

for binary in tarako-tls-attester tarako-tls-attester-test; do
    path="$measured/$binary"
    install -m755 "$(command -v "$binary")" "$path"
    fsverity enable --hash-alg=sha256 --block-size=1024 "$path"
    measurement=$(fsverity measure "$path")
    read -r digest _ <<< "$measurement"
    if ! [[ $digest =~ ^sha256:[[:xdigit:]]{64}$ ]]; then
        printf 'Unexpected fs-verity measurement: %s\n' "$measurement" >&2
        exit 1
    fi
    printf '%s %s\n' "$binary" "${digest#sha256:}"
done
