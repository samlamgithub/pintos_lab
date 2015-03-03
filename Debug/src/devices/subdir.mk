################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/devices/block.c \
../src/devices/ide.c \
../src/devices/input.c \
../src/devices/intq.c \
../src/devices/kbd.c \
../src/devices/partition.c \
../src/devices/pit.c \
../src/devices/rtc.c \
../src/devices/serial.c \
../src/devices/shutdown.c \
../src/devices/speaker.c \
../src/devices/timer.c \
../src/devices/vga.c 

OBJS += \
./src/devices/block.o \
./src/devices/ide.o \
./src/devices/input.o \
./src/devices/intq.o \
./src/devices/kbd.o \
./src/devices/partition.o \
./src/devices/pit.o \
./src/devices/rtc.o \
./src/devices/serial.o \
./src/devices/shutdown.o \
./src/devices/speaker.o \
./src/devices/timer.o \
./src/devices/vga.o 

C_DEPS += \
./src/devices/block.d \
./src/devices/ide.d \
./src/devices/input.d \
./src/devices/intq.d \
./src/devices/kbd.d \
./src/devices/partition.d \
./src/devices/pit.d \
./src/devices/rtc.d \
./src/devices/serial.d \
./src/devices/shutdown.d \
./src/devices/speaker.d \
./src/devices/timer.d \
./src/devices/vga.d 


# Each subdirectory must supply rules for building sources it contributes
src/devices/%.o: ../src/devices/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


