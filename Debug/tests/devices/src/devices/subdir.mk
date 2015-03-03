################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../tests/devices/src/devices/block.c \
../tests/devices/src/devices/ide.c \
../tests/devices/src/devices/input.c \
../tests/devices/src/devices/intq.c \
../tests/devices/src/devices/kbd.c \
../tests/devices/src/devices/partition.c \
../tests/devices/src/devices/pit.c \
../tests/devices/src/devices/rtc.c \
../tests/devices/src/devices/serial.c \
../tests/devices/src/devices/shutdown.c \
../tests/devices/src/devices/speaker.c \
../tests/devices/src/devices/timer.c \
../tests/devices/src/devices/vga.c 

OBJS += \
./tests/devices/src/devices/block.o \
./tests/devices/src/devices/ide.o \
./tests/devices/src/devices/input.o \
./tests/devices/src/devices/intq.o \
./tests/devices/src/devices/kbd.o \
./tests/devices/src/devices/partition.o \
./tests/devices/src/devices/pit.o \
./tests/devices/src/devices/rtc.o \
./tests/devices/src/devices/serial.o \
./tests/devices/src/devices/shutdown.o \
./tests/devices/src/devices/speaker.o \
./tests/devices/src/devices/timer.o \
./tests/devices/src/devices/vga.o 

C_DEPS += \
./tests/devices/src/devices/block.d \
./tests/devices/src/devices/ide.d \
./tests/devices/src/devices/input.d \
./tests/devices/src/devices/intq.d \
./tests/devices/src/devices/kbd.d \
./tests/devices/src/devices/partition.d \
./tests/devices/src/devices/pit.d \
./tests/devices/src/devices/rtc.d \
./tests/devices/src/devices/serial.d \
./tests/devices/src/devices/shutdown.d \
./tests/devices/src/devices/speaker.d \
./tests/devices/src/devices/timer.d \
./tests/devices/src/devices/vga.d 


# Each subdirectory must supply rules for building sources it contributes
tests/devices/src/devices/%.o: ../tests/devices/src/devices/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


