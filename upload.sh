#!/bin/bash
HEX=build/immurok_CH592F.hex
MAX=3

for i in $(seq 1 $MAX); do
    wlink --chip CH59X --speed low flash "$HEX" && exit 0
    echo "烧录失败 ($i/$MAX)，等待重试..."
    sleep 1
done

echo "烧录失败，已重试 $MAX 次"
exit 1
