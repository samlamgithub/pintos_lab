################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/tests/userprog/no-vm/multi-oom.c 

OBJS += \
./src/tests/userprog/no-vm/multi-oom.o 

C_DEPS += \
./src/tests/userprog/no-vm/multi-oom.d 


# Each subdirectory must supply rules for building sources it contributes
src/tests/userprog/no-vm/%.o: ../src/tests/userprog/no-vm/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


