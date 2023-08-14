sizes="\
    2000 \
    4000 \
    5000 \
    6000 \
    8000 \
    10000 \
    20000 \
    40000 \
    50000 \
    60000 \
    80000 \
    100000 \
    "

for size in $sizes; do
    cargo run -- data $size 5
done
