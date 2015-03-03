################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../tests/devices/src/tests/devices/alarm-negative.c \
../tests/devices/src/tests/devices/alarm-priority.c \
../tests/devices/src/tests/devices/alarm-simultaneous.c \
../tests/devices/src/tests/devices/alarm-wait.c \
../tests/devices/src/tests/devices/alarm-zero.c \
../tests/devices/src/tests/devices/tests.c 

OBJS += \
./tests/devices/src/tests/devices/alarm-negative.o \
./tests/devices/src/tests/devices/alarm-priority.o \
./tests/devices/src/tests/devices/alarm-simultaneous.o \
./tests/devices/src/tests/devices/alarm-wait.o \
./tests/devices/src/tests/devices/alarm-zero.o \
./tests/devices/src/tests/devices/tests.o 

C_DEPS += \
./tests/devices/src/tests/devices/alarm-negative.d \
./tests/devices/src/tests/devices/alarm-priority.d \
./tests/devices/src/tests/devices/alarm-simultaneous.d \
./tests/devices/src/tests/devices/alarm-wait.d \
./tests/devices/src/tests/devices/alarm-zero.d \
./tests/devices/src/tests/devices/tests.d 


# Each subdirectory must supply rules for building sources it contributes
tests/devices/src/tests/devices/%.o: ../tests/devices/src/tests/devices/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


