import type { MicrosoftRewardsBot } from '../index'
import { getErrorMessage } from '../util/core/Utils'
import { log as botLog } from '../util/notifications/Logger'
import { dashboardState } from './state'

export class BotController {
  private botInstance: MicrosoftRewardsBot | null = null
  private startTime?: Date
  private isStarting: boolean = false // Race condition protection

  constructor() {
    process.on('exit', () => this.stop())
  }

  private log(message: string, level: 'log' | 'warn' | 'error' = 'log'): void {
    botLog('main', 'BOT-CONTROLLER', message, level)

    dashboardState.addLog({
      timestamp: new Date().toISOString(),
      level,
      platform: 'MAIN',
      title: 'BOT-CONTROLLER',
      message
    })
  }

  public async start(): Promise<{ success: boolean; error?: string; pid?: number }> {
    // FIXED: Race condition protection - prevent multiple simultaneous start() calls
    if (this.botInstance) {
      return { success: false, error: 'Bot is already running' }
    }

    if (this.isStarting) {
      return { success: false, error: 'Bot is currently starting, please wait' }
    }

    try {
      this.isStarting = true
      this.log('🚀 Starting bot...', 'log')

      const { MicrosoftRewardsBot } = await import('../index')

      this.botInstance = new MicrosoftRewardsBot(false)
      this.startTime = new Date()
      dashboardState.setRunning(true)
      dashboardState.setBotInstance(this.botInstance)

      // Run bot asynchronously - don't block the API response
      void (async () => {
        try {
          this.log('✓ Bot initialized, starting execution...', 'log')

          await this.botInstance!.initialize()
          await this.botInstance!.run()

          this.log('✓ Bot completed successfully', 'log')
        } catch (error) {
          this.log(`Bot error: ${getErrorMessage(error)}`, 'error')
        } finally {
          this.cleanup()
        }
      })()

      return { success: true, pid: process.pid }

    } catch (error) {
      const errorMsg = getErrorMessage(error)
      this.log(`Failed to start bot: ${errorMsg}`, 'error')
      this.cleanup()
      return { success: false, error: errorMsg }
    } finally {
      this.isStarting = false
    }
  }

  public stop(): { success: boolean; error?: string } {
    if (!this.botInstance) {
      return { success: false, error: 'Bot is not running' }
    }

    try {
      this.log('🛑 Stopping bot...', 'warn')
      this.log('⚠ Note: Bot will complete current task before stopping', 'warn')

      this.cleanup()
      return { success: true }

    } catch (error) {
      const errorMsg = getErrorMessage(error)
      this.log(`Error stopping bot: ${errorMsg}`, 'error')
      this.cleanup()
      return { success: false, error: errorMsg }
    }
  }

  public async restart(): Promise<{ success: boolean; error?: string; pid?: number }> {
    this.log('🔄 Restarting bot...', 'log')

    const stopResult = this.stop()
    if (!stopResult.success && stopResult.error !== 'Bot is not running') {
      return { success: false, error: `Failed to stop: ${stopResult.error}` }
    }

    await this.wait(2000)

    return await this.start()
  }

  /**
   * Run a single account (for dashboard "run single" feature)
   * FIXED: Actually implement single account execution
   */
  public async runSingle(email: string): Promise<{ success: boolean; error?: string; pid?: number }> {
    if (this.botInstance) {
      return { success: false, error: 'Bot is already running. Stop it first.' }
    }

    if (this.isStarting) {
      return { success: false, error: 'Bot is currently starting, please wait' }
    }

    try {
      this.isStarting = true
      this.log(`🚀 Starting bot for single account: ${email}`, 'log')

      const { MicrosoftRewardsBot } = await import('../index')
      const { loadAccounts } = await import('../util/state/Load')

      // Load all accounts and filter to just this one
      const allAccounts = loadAccounts()
      const targetAccount = allAccounts.find(a => a.email === email)

      if (!targetAccount) {
        return { success: false, error: `Account ${email} not found in accounts.jsonc` }
      }

      this.botInstance = new MicrosoftRewardsBot(false)
      this.startTime = new Date()
      dashboardState.setRunning(true)
      dashboardState.setBotInstance(this.botInstance)

      // Update account status
      dashboardState.updateAccount(email, { status: 'running', errors: [] })

      // Run bot asynchronously with single account
      void (async () => {
        try {
          this.log(`✓ Bot initialized for ${email}, starting execution...`, 'log')

          await this.botInstance!.initialize()

            // Override accounts to run only this one
            ; (this.botInstance as any).accounts = [targetAccount]

          await this.botInstance!.run()

          this.log(`✓ Bot completed successfully for ${email}`, 'log')
          dashboardState.updateAccount(email, { status: 'completed' })
        } catch (error) {
          const errMsg = error instanceof Error ? error.message : String(error)
          this.log(`Bot error for ${email}: ${errMsg}`, 'error')
          dashboardState.updateAccount(email, {
            status: 'error',
            errors: [errMsg]
          })
        } finally {
          this.cleanup()
        }
      })()

      return { success: true, pid: process.pid }

    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error)
      this.log(`Failed to start bot for ${email}: ${errorMsg}`, 'error')
      dashboardState.updateAccount(email, { status: 'error', errors: [errorMsg] })
      this.cleanup()
      return { success: false, error: errorMsg }
    } finally {
      this.isStarting = false
    }
  }

  private async wait(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms))
  }

  public getStatus(): {
    running: boolean
    pid?: number
    uptime?: number
    startTime?: string
  } {
    return {
      running: !!this.botInstance,
      pid: process.pid,
      uptime: this.startTime ? Date.now() - this.startTime.getTime() : undefined,
      startTime: this.startTime?.toISOString()
    }
  }

  private cleanup(): void {
    this.botInstance = null
    this.startTime = undefined
    dashboardState.setRunning(false)
    dashboardState.setBotInstance(undefined)
  }
}

export const botController = new BotController()
