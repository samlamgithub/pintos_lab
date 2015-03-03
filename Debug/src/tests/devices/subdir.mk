################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/tests/devices/alarm-negative.c \
../src/tests/devices/alarm-priority.c \
../src/tests/devices/alarm-simultaneous.c \
../src/tests/devices/alarm-wait.c \
../src/tests/devices/alarm-zero.c \
../src/tests/devices/tests.c 

OBJS += \
./src/tests/devices/alarm-negative.o \
./src/tests/devices/alarm-priority.o \
./src/tests/devices/alarm-simultaneous.o \
./src/tests/devices/alarm-wait.o \
./src/tests/devices/alarm-zero.o \
./src/tests/devices/tests.o 

C_DEPS += \
./src/tests/devices/alarm-negative.d \
./src/tests/devices/alarm-priority.d \
./src/tests/devices/alarm-simultaneous.d \
./src/tests/devices/alarm-wait.d \
./src/tests/devices/alarm-zero.d \
./src/tests/devices/tests.d 


# Each subdirectory must supply rules for building sources it contributes
src/tests/devices/%.o: ../src/tests/devices/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


