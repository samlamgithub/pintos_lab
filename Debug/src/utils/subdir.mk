################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/utils/setitimer-helper.c \
../src/utils/squish-pty.c \
../src/utils/squish-unix.c 

OBJS += \
./src/utils/setitimer-helper.o \
./src/utils/squish-pty.o \
./src/utils/squish-unix.o 

C_DEPS += \
./src/utils/setitimer-helper.d \
./src/utils/squish-pty.d \
./src/utils/squish-unix.d 


# Each subdirectory must supply rules for building sources it contributes
src/utils/%.o: ../src/utils/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


