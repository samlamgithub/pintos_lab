################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../tests/devices/src/utils/setitimer-helper.c \
../tests/devices/src/utils/squish-pty.c \
../tests/devices/src/utils/squish-unix.c 

OBJS += \
./tests/devices/src/utils/setitimer-helper.o \
./tests/devices/src/utils/squish-pty.o \
./tests/devices/src/utils/squish-unix.o 

C_DEPS += \
./tests/devices/src/utils/setitimer-helper.d \
./tests/devices/src/utils/squish-pty.d \
./tests/devices/src/utils/squish-unix.d 


# Each subdirectory must supply rules for building sources it contributes
tests/devices/src/utils/%.o: ../tests/devices/src/utils/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


