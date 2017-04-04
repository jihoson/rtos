#!/bin/bash

declare -a devices
index=0
for _device in /sys/block/*/device; do
    if echo $(readlink -f $_device) | egrep -q "usb"; then
	devices[index]=`echo $_device | cut -f4 -d/`
    	let "index = $index + 1"
    fi
done

if [ $index == 0 ]
then
	echo "No USB device found for install PacketNgin RTOS image"
	exit
fi

echo "Choose USB device for install PacketNgin RTOS image"
count=0
for (( i = 0 ; i < ${#devices[@]} ; i++ )) ; do
	let "count = $count + 1"
	echo $count : $(udevadm info /dev/${devices[i]} | grep ID_SERIAL | head -n1 | cut -f2 -d=)
done

echo -n "Select : "
read input

if [ $input -le 0 -o $input -gt $count ]
then
	echo "Invalid index of USB device. Choose between 1 ~ $count"
	exit
fi

echo "Copying PacketNgin RTOS image..."
let "count = $count - 1"
$(sudo dcfldd if=system.img of=/dev/${devices[$count]} && sync) 
echo "Done"
